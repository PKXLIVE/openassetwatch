package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor/aggregate"
	"github.com/openassetwatch/openassetwatch/internal/sensor/capture"
	"github.com/openassetwatch/openassetwatch/internal/sensor/contract"
	"github.com/openassetwatch/openassetwatch/internal/sensor/decode"
	"github.com/openassetwatch/openassetwatch/internal/sensor/health"
	"github.com/openassetwatch/openassetwatch/internal/sensor/hubclient"
	"github.com/openassetwatch/openassetwatch/internal/sensor/spool"
)

type Config struct {
	SiteID        string
	SensorID      string
	SensorName    string
	SensorVersion string
	BatchSize     int
	BatchInterval time.Duration
	RetryInitial  time.Duration
	RetryMaximum  time.Duration
}

type Runner struct {
	Config     Config
	Source     capture.Source
	Aggregator *aggregate.Aggregator
	Spool      *spool.Queue
	Hub        *hubclient.Client
	Health     *health.Tracker
	Now        func() time.Time
	ObservedAt func() time.Time
}

func (r *Runner) Run(ctx context.Context) error {
	if err := r.validate(); err != nil {
		return err
	}
	defer r.Health.Stop()
	if err := r.deliverPending(ctx); err != nil {
		r.Health.HubError(err.Error())
	}
	nextFlush := r.now().Add(r.Config.BatchInterval)
	for {
		// The replay clock is deliberately fixed so its batch ID is stable.
		// Use a relative timeout for capture waits so a historical logical
		// observation timestamp never becomes an already-expired wall-clock
		// context deadline.
		wait := nextFlush.Sub(r.now())
		if wait <= 0 {
			if flushErr := r.flushAndDeliver(ctx, nextFlush); flushErr != nil {
				r.Health.HubError(flushErr.Error())
			}
			nextFlush = r.now().Add(r.Config.BatchInterval)
			continue
		}
		packetContext, cancel := context.WithTimeout(ctx, wait)
		packet, err := r.Source.Next(packetContext)
		cancel()
		switch {
		case err == nil:
			evidence, decodeErr := decode.Frame(packet.Data, packet.ObservedAt)
			clear(packet.Data)
			packet.Data = nil
			r.Health.PacketResult(decodeErr == nil && len(evidence) > 0, decodeErr != nil)
			if decodeErr != nil {
				r.Health.CaptureError(decodeErr.Error())
			} else {
				for _, item := range evidence {
					if addErr := r.Aggregator.Add(item); addErr != nil && !errors.Is(addErr, aggregate.ErrCapacity) {
						r.Health.CaptureError(addErr.Error())
					}
				}
			}
		case errors.Is(err, io.EOF):
			if flushErr := r.flushAndDeliver(ctx, r.observedAt()); flushErr != nil {
				return flushErr
			}
			return nil
		case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
			if flushErr := r.flushAndDeliver(ctx, nextFlush); flushErr != nil {
				r.Health.HubError(flushErr.Error())
			}
			nextFlush = r.now().Add(r.Config.BatchInterval)
			continue
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			r.Health.CaptureError(err.Error())
			return err
		}
		if !r.now().Before(nextFlush) {
			if err := r.flushAndDeliver(ctx, nextFlush); err != nil {
				r.Health.HubError(err.Error())
			}
			nextFlush = r.now().Add(r.Config.BatchInterval)
		}
	}
}

func (r *Runner) flushAndDeliver(ctx context.Context, observedAt time.Time) error {
	assets := r.Aggregator.Snapshot(observedAt, r.Config.BatchSize)
	if len(assets) > 0 {
		batchID, err := contract.BatchID(r.Config.SensorID, observedAt.UTC(), assets)
		if err != nil {
			return err
		}
		batch := contract.Batch{
			SchemaVersion: contract.SchemaVersion, ObservationBatchID: batchID,
			SiteID: r.Config.SiteID, SensorID: r.Config.SensorID, SensorName: r.Config.SensorName,
			SensorType: "passive-network-sensor", SensorVersion: r.Config.SensorVersion,
			ObservedAt: observedAt.UTC(), ObservationSource: "passive-network",
			DeliveryState: "live", Confidence: batchConfidence(assets), Assets: assets,
		}
		if _, err := r.Spool.Enqueue(batch, r.now()); err != nil {
			if errors.Is(err, spool.ErrFull) {
				r.updateQueueState("spool is full; new normalized batch was not queued", true)
			}
			return err
		}
		r.Health.Observations(len(assets))
	}
	return r.deliverPending(ctx)
}

func (r *Runner) deliverPending(ctx context.Context) error {
	for {
		entry, err := r.Spool.Next(r.now())
		if errors.Is(err, spool.ErrEmpty) {
			r.updateQueue("")
			return nil
		}
		if err != nil {
			r.updateQueue(err.Error())
			return err
		}
		batch := entry.Batch
		if entry.Attempts > 0 {
			batch.DeliveryState = "cached-retry"
		}
		_, err = r.Hub.Send(ctx, batch)
		if err == nil {
			if err := r.Spool.Remove(entry); err != nil {
				return err
			}
			r.Health.Sent(r.now())
			r.updateQueue("")
			continue
		}
		retryable, class := hubclient.Retryable(err)
		r.Health.HubError(err.Error())
		if !retryable {
			r.updateQueue("queued batch requires operator attention")
			return err
		}
		delay := hubclient.Backoff(entry.Attempts, r.Config.RetryInitial, r.Config.RetryMaximum)
		if err := r.Spool.RecordRetry(entry, r.now().Add(delay), class); err != nil {
			return err
		}
		r.updateQueue("hub delivery retry scheduled")
		return err
	}
}

func (r *Runner) updateQueue(warning string) {
	r.updateQueueState(warning, false)
}

func (r *Runner) updateQueueState(warning string, overflow bool) {
	stats, err := r.Spool.Stats()
	if err != nil {
		r.Health.QueueState(0, 0, err.Error(), overflow)
		return
	}
	r.Health.QueueState(stats.Items, stats.Capacity, warning, overflow)
}

func (r *Runner) validate() error {
	if r.Source == nil || r.Aggregator == nil || r.Spool == nil || r.Hub == nil || r.Health == nil {
		return errors.New("sensor runner dependencies are required")
	}
	if r.Config.SiteID == "" || r.Config.SensorID == "" || r.Config.SensorName == "" {
		return errors.New("sensor runner identity is required")
	}
	if err := contract.ValidateSiteID(r.Config.SiteID); err != nil {
		return err
	}
	if err := contract.ValidateSensorID(r.Config.SensorID); err != nil {
		return err
	}
	if r.Config.BatchSize < 1 || r.Config.BatchSize > contract.MaxAssets || r.Config.BatchInterval <= 0 {
		return errors.New("sensor runner batch settings are invalid")
	}
	return nil
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Runner) observedAt() time.Time {
	if r.ObservedAt != nil {
		return r.ObservedAt().UTC()
	}
	return r.now()
}

func batchConfidence(assets []contract.Asset) float64 {
	if len(assets) == 0 {
		return 0.5
	}
	total := 0.0
	count := 0
	for _, asset := range assets {
		for _, item := range asset.Evidence {
			total += item.Confidence
			count++
		}
	}
	if count == 0 {
		return 0.5
	}
	value := total / float64(count)
	if value < 0.5 {
		return 0.5
	}
	if value > 0.95 {
		return 0.95
	}
	return value
}

func (r *Runner) Summary() string {
	state := r.Health.Snapshot()
	return fmt.Sprintf("sensor %s observed %d packets, decoded %d, generated %d observations, sent %d batches, queued %d",
		state.SensorID, state.PacketsObserved, state.PacketsDecoded, state.ObservationsGenerated, state.BatchesSent, state.BatchesQueued)
}
