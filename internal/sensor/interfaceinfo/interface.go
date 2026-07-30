// Package interfaceinfo inspects capture interfaces without opening a packet
// socket or changing any interface state.
package interfaceinfo

import (
	"errors"
	"net"
	"sort"
	"strings"
	"unicode"
)

const MaxInterfaces = 1024

type Info struct {
	Name             string `json:"name"`
	Index            int    `json:"index"`
	Up               bool   `json:"up"`
	Loopback         bool   `json:"loopback"`
	MACAddress       string `json:"mac_address,omitempty"`
	Promiscuous      bool   `json:"promiscuous"`
	PromiscuousKnown bool   `json:"promiscuous_known"`
	CaptureSuitable  bool   `json:"capture_suitable"`
}

type CapabilityState struct {
	Platform          string   `json:"platform"`
	InspectionSource  string   `json:"inspection_source"`
	Supported         bool     `json:"supported"`
	Required          []string `json:"required"`
	NetRawEffective   bool     `json:"cap_net_raw_effective"`
	NetAdminEffective bool     `json:"cap_net_admin_effective"`
	Sufficient        bool     `json:"sufficient"`
}

type Validation struct {
	Interface    Info            `json:"interface"`
	Exists       bool            `json:"exists"`
	Capabilities CapabilityState `json:"capabilities"`
	Valid        bool            `json:"valid"`
	Warnings     []string        `json:"warnings"`
}

func List() ([]Info, error) {
	values, err := net.Interfaces()
	if err != nil {
		return nil, errors.New("list network interfaces")
	}
	if len(values) > MaxInterfaces {
		return nil, errors.New("network interface count exceeds safety limit")
	}
	result := make([]Info, 0, len(values))
	for _, value := range values {
		if !safeName(value.Name) {
			continue
		}
		up := value.Flags&net.FlagUp != 0
		loopback := value.Flags&net.FlagLoopback != 0
		mac := ""
		if len(value.HardwareAddr) == 6 {
			mac = value.HardwareAddr.String()
		}
		promiscuous, promiscuousKnown := platformPromiscuous(value.Name)
		result = append(result, Info{
			Name: value.Name, Index: value.Index, Up: up, Loopback: loopback,
			MACAddress: mac, Promiscuous: promiscuous, PromiscuousKnown: promiscuousKnown,
			CaptureSuitable: up && !loopback,
		})
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Index != result[right].Index {
			return result[left].Index < result[right].Index
		}
		return result[left].Name < result[right].Name
	})
	return result, nil
}

func Validate(name string) (Validation, error) {
	if !safeName(name) {
		return Validation{}, errors.New("interface must be an explicit safe name of at most 64 characters")
	}
	values, err := List()
	if err != nil {
		return Validation{}, err
	}
	capabilities := EffectiveCapabilities()
	for _, value := range values {
		if value.Name != name {
			continue
		}
		warnings := make([]string, 0, 2)
		if !value.Up {
			warnings = append(warnings, "interface is not up")
		}
		if value.Loopback {
			warnings = append(warnings, "loopback interfaces are not suitable SPAN destinations")
		}
		if value.PromiscuousKnown && !value.Promiscuous {
			warnings = append(warnings, "interface is not in promiscuous mode; mirrored unicast frames may be filtered by the NIC")
		}
		if capabilities.Supported && !capabilities.NetRawEffective {
			warnings = append(warnings, "CAP_NET_RAW is not effective for this process")
		}
		return Validation{
			Interface: value, Exists: true, Capabilities: capabilities,
			Valid:    value.CaptureSuitable && (!capabilities.Supported || capabilities.Sufficient),
			Warnings: warnings,
		}, nil
	}
	return Validation{
		Interface: Info{Name: name}, Exists: false, Capabilities: capabilities,
		Warnings: []string{"interface does not exist"},
	}, nil
}

func safeName(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 64 || strings.ContainsAny(value, `/\`) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
