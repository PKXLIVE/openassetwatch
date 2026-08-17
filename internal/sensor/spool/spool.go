package spool

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor/contract"
	"github.com/openassetwatch/openassetwatch/internal/sensor/safefile"
)

var (
	ErrFull    = errors.New("sensor spool capacity reached")
	ErrEmpty   = errors.New("sensor spool is empty")
	ErrCorrupt = errors.New("corrupt sensor spool entry quarantined")
)

const (
	MaxItemsAbsolute       = 10_000
	MaxBytesAbsolute int64 = 10 << 30
	MaxScanEntries         = 10_000
	MaxAttempts            = 100_000
	MaxEntryBytes          = contract.MaxBodyBytes + (64 << 10)
	MaxRetryDelay          = 24 * time.Hour
)

type Config struct {
	Path     string
	MaxItems int
	MaxBytes int64
}

type Queue struct {
	mu        sync.Mutex
	root      *os.Root
	maxItems  int
	maxBytes  int64
	scanLimit int
}

type Entry struct {
	Name           string
	Batch          contract.Batch
	Attempts       int
	NextAttemptAt  time.Time
	LastErrorClass string
}

type envelope struct {
	SchemaVersion  string         `json:"schema_version"`
	CreatedAt      time.Time      `json:"created_at"`
	Attempts       int            `json:"attempts"`
	NextAttemptAt  *time.Time     `json:"next_attempt_at,omitempty"`
	LastErrorClass string         `json:"last_error_class,omitempty"`
	Batch          contract.Batch `json:"batch"`
}

type Stats struct {
	Items    int
	Bytes    int64
	Capacity float64
}

func Open(config Config) (*Queue, error) {
	if strings.TrimSpace(config.Path) == "" || config.MaxItems < 1 || config.MaxItems > MaxItemsAbsolute || config.MaxBytes < 1 || config.MaxBytes > MaxBytesAbsolute {
		return nil, errors.New("spool path and bounded limits are required")
	}
	root, err := safefile.OpenPrivateRoot(config.Path, true)
	if err != nil {
		return nil, err
	}
	queue := &Queue{root: root, maxItems: config.MaxItems, maxBytes: config.MaxBytes, scanLimit: MaxScanEntries}
	if err := queue.recoverTemps(); err != nil {
		_ = root.Close()
		return nil, err
	}
	return queue, nil
}

func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.root.Close()
}

func (q *Queue) Enqueue(batch contract.Batch, now time.Time) (string, error) {
	if now.IsZero() {
		return "", errors.New("spool creation timestamp is required")
	}
	if err := batch.Validate(); err != nil {
		return "", err
	}
	payload := envelope{SchemaVersion: "oaw.sensor-spool.v1", CreatedAt: now.UTC(), Batch: batch}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal spool entry: %w", err)
	}
	if len(data) > MaxEntryBytes {
		return "", errors.New("spool entry exceeds size limit")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	stats, err := q.statsLocked()
	if err != nil {
		return "", err
	}
	if stats.Items >= q.maxItems || stats.Bytes+int64(len(data)) > q.maxBytes {
		return "", ErrFull
	}
	suffix, err := randomSuffix()
	if err != nil {
		return "", err
	}
	name := now.UTC().Format("20060102T150405.000000000Z") + "-" + suffix + ".json"
	if err := q.atomicWrite(name, append(data, '\n'), false); err != nil {
		return "", err
	}
	return name, nil
}

func (q *Queue) Next(now time.Time) (Entry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	names, err := q.pendingNames()
	if err != nil {
		return Entry{}, err
	}
	for _, name := range names {
		item, err := q.readEnvelope(name)
		if err != nil {
			badName, suffixErr := q.corruptName(name)
			if suffixErr != nil {
				return Entry{}, errors.Join(ErrCorrupt, err, suffixErr)
			}
			if renameErr := q.root.Rename(name, badName); renameErr != nil {
				return Entry{}, errors.Join(ErrCorrupt, err, renameErr)
			}
			_ = q.syncDirectory()
			return Entry{}, errors.Join(ErrCorrupt, err)
		}
		if item.NextAttemptAt != nil && item.NextAttemptAt.After(now.UTC()) {
			continue
		}
		return Entry{
			Name: name, Batch: item.Batch, Attempts: item.Attempts,
			NextAttemptAt: timeValue(item.NextAttemptAt), LastErrorClass: item.LastErrorClass,
		}, nil
	}
	return Entry{}, ErrEmpty
}

func (q *Queue) RecordRetry(entry Entry, nextAttempt time.Time, errorClass string) error {
	if !safeEntryName(entry.Name) || nextAttempt.IsZero() || nextAttempt.After(time.Now().UTC().Add(MaxRetryDelay)) {
		return errors.New("invalid spool retry metadata")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	current, err := q.readEnvelope(entry.Name)
	if err != nil {
		return err
	}
	if current.Attempts >= MaxAttempts {
		return errors.New("spool retry limit reached")
	}
	current.Attempts++
	value := nextAttempt.UTC()
	current.NextAttemptAt = &value
	current.LastErrorClass = cleanErrorClass(errorClass)
	data, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("marshal spool retry metadata: %w", err)
	}
	return q.atomicWrite(entry.Name, append(data, '\n'), true)
}

func (q *Queue) Remove(entry Entry) error {
	if !safeEntryName(entry.Name) {
		return errors.New("invalid spool entry name")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	before, err := q.root.Lstat(entry.Name)
	if err != nil {
		return err
	}
	file, err := q.root.Open(entry.Name)
	if err != nil {
		return err
	}
	after, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil {
		return statErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := safefile.ValidateOpenedFile(before, after); err != nil {
		return err
	}
	if err := q.root.Remove(entry.Name); err != nil {
		return fmt.Errorf("remove acknowledged spool entry: %w", err)
	}
	return q.syncDirectory()
}

func (q *Queue) Stats() (Stats, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.statsLocked()
}

func (q *Queue) statsLocked() (Stats, error) {
	entries, err := q.readEntriesBounded()
	if err != nil {
		return Stats{}, fmt.Errorf("list spool: %w", err)
	}
	stats := Stats{}
	for _, item := range entries {
		info, err := q.root.Lstat(item.Name())
		if err != nil {
			return Stats{}, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return Stats{}, fmt.Errorf("unsafe non-regular spool entry %q", item.Name())
		}
		if err := safefile.ValidateOwnerAndMode(info, false); err != nil {
			return Stats{}, fmt.Errorf("unsafe spool entry %q: %w", item.Name(), err)
		}
		if links := safefile.LinkCount(info); links > 1 {
			return Stats{}, fmt.Errorf("unsafe multiply-linked spool entry %q", item.Name())
		}
		if strings.HasSuffix(item.Name(), ".json") {
			stats.Items++
		}
		stats.Bytes += info.Size()
	}
	itemRatio := float64(stats.Items) / float64(q.maxItems)
	byteRatio := float64(stats.Bytes) / float64(q.maxBytes)
	if itemRatio > byteRatio {
		stats.Capacity = itemRatio
	} else {
		stats.Capacity = byteRatio
	}
	return stats, nil
}

func (q *Queue) pendingNames() ([]string, error) {
	entries, err := q.readEntriesBounded()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func (q *Queue) readEnvelope(name string) (envelope, error) {
	before, err := q.root.Lstat(name)
	if err != nil {
		return envelope{}, err
	}
	if before.Size() < 1 || before.Size() > MaxEntryBytes {
		return envelope{}, errors.New("spool entry has invalid size")
	}
	file, err := q.root.Open(name)
	if err != nil {
		return envelope{}, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return envelope{}, err
	}
	if err := safefile.ValidateOpenedFile(before, after); err != nil {
		return envelope{}, err
	}
	decoder := json.NewDecoder(io.LimitReader(file, MaxEntryBytes))
	decoder.DisallowUnknownFields()
	var item envelope
	if err := decoder.Decode(&item); err != nil {
		return envelope{}, fmt.Errorf("decode spool entry: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return envelope{}, errors.New("decode spool entry: trailing JSON data is not allowed")
	}
	if item.SchemaVersion != "oaw.sensor-spool.v1" || item.CreatedAt.IsZero() || item.Attempts < 0 || item.Attempts > MaxAttempts {
		return envelope{}, errors.New("spool metadata is invalid")
	}
	if item.Attempts == 0 && (item.NextAttemptAt != nil || item.LastErrorClass != "") {
		return envelope{}, errors.New("spool retry metadata is invalid")
	}
	if item.Attempts > 0 && (item.NextAttemptAt == nil || !validErrorClass(item.LastErrorClass)) {
		return envelope{}, errors.New("spool retry metadata is invalid")
	}
	if item.NextAttemptAt != nil && item.NextAttemptAt.After(time.Now().UTC().Add(MaxRetryDelay)) {
		return envelope{}, errors.New("spool retry timestamp exceeds safety limit")
	}
	if err := item.Batch.Validate(); err != nil {
		return envelope{}, err
	}
	return item, nil
}

func (q *Queue) atomicWrite(name string, data []byte, replace bool) error {
	if !safeEntryName(name) || len(data) > MaxEntryBytes {
		return errors.New("invalid or oversized spool entry")
	}
	suffix, err := randomSuffix()
	if err != nil {
		return err
	}
	tempName := ".tmp-" + suffix
	file, err := q.root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create spool temporary file: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = q.root.Remove(tempName)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write spool temporary file: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || safefile.LinkCount(info) > 1 {
		_ = file.Close()
		return errors.New("spool temporary file failed regular-file validation")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync spool temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close spool temporary file: %w", err)
	}
	if !replace {
		if _, err := q.root.Lstat(name); err == nil {
			return errors.New("spool entry already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := q.root.Rename(tempName, name); err != nil {
		return fmt.Errorf("publish spool entry atomically: %w", err)
	}
	cleanup = false
	return q.syncDirectory()
}

func (q *Queue) recoverTemps() error {
	entries, err := q.readEntriesBounded()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		info, err := q.root.Lstat(entry.Name())
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("unsafe interrupted spool entry %q", entry.Name())
		}
		if err := safefile.ValidateOwnerAndMode(info, false); err != nil {
			return fmt.Errorf("unsafe interrupted spool entry %q: %w", entry.Name(), err)
		}
		if links := safefile.LinkCount(info); links > 1 {
			return fmt.Errorf("unsafe multiply-linked interrupted spool entry %q", entry.Name())
		}
		name, err := q.corruptName(entry.Name())
		if err != nil {
			return err
		}
		if err := q.root.Rename(entry.Name(), name); err != nil {
			return fmt.Errorf("quarantine interrupted spool write: %w", err)
		}
	}
	return q.syncDirectory()
}

func (q *Queue) readEntriesBounded() ([]fs.DirEntry, error) {
	directory, err := q.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	limit := q.scanLimit
	if limit <= 0 || limit > MaxScanEntries {
		limit = MaxScanEntries
	}
	entries, err := directory.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > limit {
		return nil, errors.New("spool directory entry count exceeds safety limit")
	}
	return entries, nil
}

func safeEntryName(name string) bool {
	return name != "" && len(name) <= 240 && name != "." && name != ".." && !strings.ContainsAny(name, `/\\`) && !strings.HasPrefix(name, "-")
}

func (q *Queue) corruptName(name string) (string, error) {
	suffix, err := randomSuffix()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(name))
	return "corrupt-" + hex.EncodeToString(digest[:8]) + "-" + suffix + ".bad", nil
}

func (q *Queue) syncDirectory() error {
	directory, err := q.root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := syncDirectoryFile(directory); err != nil {
		return fmt.Errorf("sync spool directory: %w", err)
	}
	return nil
}

func randomSuffix() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate spool file name: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func cleanErrorClass(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "network", "timeout", "rate-limit", "server", "temporary":
		return value
	default:
		return "temporary"
	}
}

func validErrorClass(value string) bool {
	switch value {
	case "network", "timeout", "rate-limit", "server", "temporary":
		return true
	default:
		return false
	}
}

func timeValue(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.UTC()
}
