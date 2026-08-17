//go:build linux

package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const ethernetProtocolAll = 0x0003

type liveSource struct {
	mu            sync.Mutex
	fd            int
	interfaceName string
	closed        bool
}

func NewLive(interfaceName string) (Source, error) {
	if interfaceName == "" {
		return nil, errors.New("capture interface is required for live mode")
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("resolve capture interface: %w", err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(htons(ethernetProtocolAll)))
	if err != nil {
		return nil, fmt.Errorf("open passive capture socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(ethernetProtocolAll), Ifindex: iface.Index}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind passive capture socket: %w", err)
	}
	return &liveSource{fd: fd, interfaceName: interfaceName}, nil
}

func (s *liveSource) Next(ctx context.Context) (Packet, error) {
	buffer := make([]byte, MaxFrameBytes)
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return Packet{}, errors.New("capture source is closed")
		}
		fd := s.fd
		s.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return Packet{}, err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, 250)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return Packet{}, fmt.Errorf("poll passive capture socket: %w", err)
		}
		if ready == 0 {
			continue
		}
		n, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			return Packet{}, fmt.Errorf("read passive capture socket: %w", err)
		}
		if n == 0 {
			continue
		}
		return Packet{Data: append([]byte(nil), buffer[:n]...), ObservedAt: time.Now().UTC()}, nil
	}
}

func (s *liveSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return unix.Close(s.fd)
}

func (s *liveSource) Name() string { return "linux-af-packet:" + s.interfaceName }

func htons(value uint16) uint16 { return value<<8 | value>>8 }
