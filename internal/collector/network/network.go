package network

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/models"
)

const (
	sourceNetInterfaces  = "go_net_interfaces"
	sourceProcARP        = "proc_net_arp"
	sourceProcRoute      = "proc_net_route"
	sourceArpA           = "arp_a"
	sourceGetNetNeighbor = "windows_get_net_neighbor"
	sourceGetNetRoute    = "windows_get_net_route"
	sourceRouteDefault   = "darwin_route_default"
	darwinARPPath        = "/usr/sbin/arp"
	darwinRoutePath      = "/sbin/route"
	localCommandTimeout  = 5 * time.Second
	localCommandMaxBytes = 1024 * 1024
)

var errCommandOutputTooLarge = errors.New("local command output exceeded maximum size")

var newLocalCommand = exec.CommandContext

type InterfaceInventory struct {
	PrimaryInterfaces []models.NetworkInterface
	IPAddresses       []models.IPAddressObservation
	MACAddresses      []models.MACAddressObservation
}

func CollectInterfaces() InterfaceInventory {
	return CollectInterfacesAt(time.Now().UTC())
}

func CollectInterfacesAt(collectedAt time.Time) InterfaceInventory {
	interfaces, err := net.Interfaces()
	if err != nil {
		return InterfaceInventory{}
	}

	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Index < interfaces[j].Index
	})

	inventory := InterfaceInventory{}
	for _, iface := range interfaces {
		addresses := interfaceAddresses(iface, collectedAt)
		mac := normalizeMAC(iface.HardwareAddr.String())

		if mac != "" {
			inventory.MACAddresses = append(inventory.MACAddresses, models.MACAddressObservation{
				Address:     mac,
				Interface:   iface.Name,
				Source:      sourceNetInterfaces,
				CollectedAt: collectedAt,
			})
		}
		inventory.IPAddresses = append(inventory.IPAddresses, addresses...)

		if !isPrimaryInterface(iface, addresses) {
			continue
		}

		inventory.PrimaryInterfaces = append(inventory.PrimaryInterfaces, models.NetworkInterface{
			Name:        iface.Name,
			Index:       iface.Index,
			MACAddress:  mac,
			Flags:       interfaceFlags(iface.Flags),
			IPAddresses: addresses,
			Source:      sourceNetInterfaces,
			CollectedAt: collectedAt,
		})
	}

	return inventory
}

func CollectDefaultGateway() *models.DefaultGatewayObservation {
	return CollectDefaultGatewayAt(time.Now().UTC())
}

func CollectDefaultGatewayAt(collectedAt time.Time) *models.DefaultGatewayObservation {
	var gateway *models.DefaultGatewayObservation
	switch runtime.GOOS {
	case "linux":
		gateway = defaultGatewayFromProcRoute(sourceProcRoute)
	case "windows":
		gateway = defaultGatewayFromWindowsRoute()
	case "darwin":
		gateway = defaultGatewayFromDarwinRoute()
	default:
		return nil
	}
	if gateway != nil {
		gateway.CollectedAt = collectedAt
	}
	return gateway
}

func CollectNeighbors() []models.NetworkNeighbor {
	return CollectNeighborsAt(time.Now().UTC())
}

// CollectNeighborsAt reads local neighbor caches only. It does not scan CIDRs,
// open sockets, inject packets, or ask the OS to discover new neighbors.
func CollectNeighborsAt(collectedAt time.Time) []models.NetworkNeighbor {
	var entries []models.NetworkNeighbor

	switch runtime.GOOS {
	case "linux":
		entries = neighborsFromProcARP(sourceProcARP)
	case "windows":
		entries = append(entries, neighborsFromWindowsGetNetNeighbor()...)
		entries = append(entries, neighborsFromArpCommand()...)
	case "darwin":
		entries = neighborsFromArpCommand()
	default:
		entries = neighborsFromArpCommand()
	}

	return stampNeighbors(deduplicateNeighbors(entries), collectedAt)
}

func interfaceAddresses(iface net.Interface, collectedAt time.Time) []models.IPAddressObservation {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}

	observations := make([]models.IPAddressObservation, 0, len(addrs))
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		if isIgnoredLocalIP(ip) {
			continue
		}
		family := "ipv6"
		if ip.To4() != nil {
			family = "ipv4"
		}
		observations = append(observations, models.IPAddressObservation{
			Address:     ip.String(),
			Family:      family,
			Interface:   iface.Name,
			Source:      sourceNetInterfaces,
			CollectedAt: collectedAt,
		})
	}
	return observations
}

func interfaceFlags(flags net.Flags) []string {
	values := []string{}
	if flags&net.FlagUp != 0 {
		values = append(values, "up")
	}
	if flags&net.FlagBroadcast != 0 {
		values = append(values, "broadcast")
	}
	if flags&net.FlagLoopback != 0 {
		values = append(values, "loopback")
	}
	if flags&net.FlagPointToPoint != 0 {
		values = append(values, "point_to_point")
	}
	if flags&net.FlagMulticast != 0 {
		values = append(values, "multicast")
	}
	return values
}

func isPrimaryInterface(iface net.Interface, addresses []models.IPAddressObservation) bool {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	return len(addresses) > 0 || len(iface.HardwareAddr) > 0
}

func isIgnoredLocalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast()
}

func defaultGatewayFromProcRoute(path string) *models.DefaultGatewayObservation {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	type route struct {
		gateway string
		iface   string
		metric  int
	}

	var selected *route
	for index, line := range strings.Split(string(data), "\n") {
		if index == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[1] != "00000000" || fields[2] == "00000000" {
			continue
		}
		gateway, ok := ipv4FromLittleEndianHex(fields[2])
		if !ok {
			continue
		}
		metric, _ := strconv.Atoi(fields[6])
		candidate := &route{gateway: gateway, iface: fields[0], metric: metric}
		if selected == nil || candidate.metric < selected.metric {
			selected = candidate
		}
	}

	if selected == nil {
		return nil
	}
	return &models.DefaultGatewayObservation{
		Address:   selected.gateway,
		Interface: selected.iface,
		Source:    sourceProcRoute,
	}
}

func defaultGatewayFromWindowsRoute() *models.DefaultGatewayObservation {
	output, err := windowsDefaultRouteOutput()
	if err != nil || strings.TrimSpace(output) == "" {
		return nil
	}

	var row struct {
		NextHop        string `json:"NextHop"`
		InterfaceAlias string `json:"InterfaceAlias"`
		InterfaceIndex int    `json:"InterfaceIndex"`
	}
	if err := json.Unmarshal([]byte(output), &row); err != nil {
		return nil
	}
	if net.ParseIP(row.NextHop) == nil || row.NextHop == "0.0.0.0" {
		return nil
	}
	return &models.DefaultGatewayObservation{
		Address:        row.NextHop,
		Interface:      row.InterfaceAlias,
		InterfaceIndex: row.InterfaceIndex,
		Source:         sourceGetNetRoute,
	}
}

func defaultGatewayFromDarwinRoute() *models.DefaultGatewayObservation {
	output, err := darwinDefaultRouteOutput()
	if err != nil {
		return nil
	}
	return parseDarwinDefaultRoute(output)
}

func parseDarwinDefaultRoute(output string) *models.DefaultGatewayObservation {
	observation := models.DefaultGatewayObservation{Source: sourceRouteDefault}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(fields) != 2 {
			continue
		}
		key := strings.TrimSpace(fields[0])
		value := strings.TrimSpace(fields[1])
		switch key {
		case "gateway":
			observation.Address = value
		case "interface":
			observation.Interface = value
		}
	}
	if observation.Address == "" {
		return nil
	}
	return &observation
}

func neighborsFromProcARP(path string) []models.NetworkNeighbor {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseProcARP(string(data))
}

func parseProcARP(output string) []models.NetworkNeighbor {
	entries := []models.NetworkNeighbor{}
	for index, line := range strings.Split(output, "\n") {
		if index == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		entries = append(entries, normalizeNeighbor(fields[0], fields[3], fields[5], fields[2], sourceProcARP))
	}
	return filterNeighbors(entries)
}

func neighborsFromWindowsGetNetNeighbor() []models.NetworkNeighbor {
	output, err := windowsNeighborOutput()
	if err != nil || strings.TrimSpace(output) == "" {
		return nil
	}
	return parseWindowsGetNetNeighbor(output)
}

func parseWindowsGetNetNeighbor(output string) []models.NetworkNeighbor {
	var rows []struct {
		IPAddress        string `json:"IPAddress"`
		LinkLayerAddress string `json:"LinkLayerAddress"`
		InterfaceAlias   string `json:"InterfaceAlias"`
		State            string `json:"State"`
	}
	if err := json.Unmarshal([]byte(output), &rows); err != nil {
		var row struct {
			IPAddress        string `json:"IPAddress"`
			LinkLayerAddress string `json:"LinkLayerAddress"`
			InterfaceAlias   string `json:"InterfaceAlias"`
			State            string `json:"State"`
		}
		if err := json.Unmarshal([]byte(output), &row); err != nil {
			return nil
		}
		rows = append(rows, row)
	}

	entries := make([]models.NetworkNeighbor, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, normalizeNeighbor(row.IPAddress, row.LinkLayerAddress, row.InterfaceAlias, row.State, sourceGetNetNeighbor))
	}
	return filterNeighbors(entries)
}

func neighborsFromArpCommand() []models.NetworkNeighbor {
	output, err := arpAOutput()
	if err != nil {
		return nil
	}
	return parseArpA(output)
}

func parseArpA(output string) []models.NetworkNeighbor {
	entries := []models.NetworkNeighbor{}
	currentInterface := ""

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Interface:") {
			// Windows arp prints the local interface address here, not the
			// interface name. Keep the field empty rather than mislabel it.
			currentInterface = ""
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 && net.ParseIP(fields[0]) != nil {
			entries = append(entries, normalizeNeighbor(fields[0], fields[1], currentInterface, fields[2], sourceArpA))
			continue
		}

		if strings.Contains(line, " at ") {
			ipAddress := ""
			macAddress := ""
			iface := ""
			for index, field := range fields {
				candidate := strings.Trim(field, "()")
				if ipAddress == "" && net.ParseIP(candidate) != nil {
					ipAddress = candidate
				}
				if macAddress == "" && strings.Contains(field, ":") {
					macAddress = field
				}
				if field == "on" && index+1 < len(fields) {
					iface = fields[index+1]
				}
			}
			entries = append(entries, normalizeNeighbor(ipAddress, macAddress, iface, "", sourceArpA))
		}
	}

	return filterNeighbors(entries)
}

func normalizeNeighbor(ipAddress string, macAddress string, iface string, state string, source string) models.NetworkNeighbor {
	return models.NetworkNeighbor{
		IPAddress:  strings.TrimSpace(ipAddress),
		MACAddress: normalizeMAC(macAddress),
		Interface:  strings.TrimSpace(iface),
		State:      strings.ToLower(strings.TrimSpace(state)),
		Source:     source,
		Sources:    []string{source},
	}
}

func stampNeighbors(entries []models.NetworkNeighbor, collectedAt time.Time) []models.NetworkNeighbor {
	for index := range entries {
		entries[index].CollectedAt = collectedAt
	}
	return entries
}

func filterNeighbors(entries []models.NetworkNeighbor) []models.NetworkNeighbor {
	filtered := make([]models.NetworkNeighbor, 0, len(entries))
	for _, entry := range entries {
		if isIgnoredNeighborIP(entry.IPAddress) || isIgnoredNeighborMAC(entry.MACAddress) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func deduplicateNeighbors(entries []models.NetworkNeighbor) []models.NetworkNeighbor {
	byKey := map[string]int{}
	result := make([]models.NetworkNeighbor, 0, len(entries))
	for _, entry := range filterNeighbors(entries) {
		key := entry.IPAddress + "|" + entry.MACAddress
		if index, ok := byKey[key]; ok {
			existing := &result[index]
			if existing.Interface == "" {
				existing.Interface = entry.Interface
			}
			if existing.State == "" {
				existing.State = entry.State
			}
			existing.Sources = appendMissing(existing.Sources, entry.Sources...)
			continue
		}
		byKey[key] = len(result)
		result = append(result, entry)
	}
	return result
}

func appendMissing(values []string, candidates ...string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		values = append(values, candidate)
		seen[candidate] = struct{}{}
	}
	return values
}

func isIgnoredNeighborIP(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil || ip.To4() == nil {
		return true
	}
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || value == "255.255.255.255"
}

func isIgnoredNeighborMAC(value string) bool {
	mac := normalizeMAC(value)
	if mac == "" || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return true
	}
	return strings.HasPrefix(mac, "01:00:5e:") || strings.HasPrefix(mac, "33:33:")
}

func normalizeMAC(value string) string {
	text := strings.ToLower(strings.TrimSpace(value))
	switch text {
	case "", "(incomplete)", "<incomplete>", "incomplete", "none", "null":
		return ""
	}
	text = strings.ReplaceAll(text, "-", ":")
	if hw, err := net.ParseMAC(text); err == nil && len(hw) == 6 {
		return hw.String()
	}

	compact := strings.NewReplacer(":", "", ".", "").Replace(text)
	if len(compact) != 12 {
		return ""
	}
	hw, err := net.ParseMAC(compact[0:2] + ":" + compact[2:4] + ":" + compact[4:6] + ":" + compact[6:8] + ":" + compact[8:10] + ":" + compact[10:12])
	if err != nil || len(hw) != 6 {
		return ""
	}
	return hw.String()
}

func ipv4FromLittleEndianHex(value string) (string, bool) {
	if len(value) != 8 {
		return "", false
	}
	parts := []string{value[6:8], value[4:6], value[2:4], value[0:2]}
	octets := make([]string, 0, 4)
	for _, part := range parts {
		parsed, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return "", false
		}
		octets = append(octets, strconv.Itoa(int(parsed)))
	}
	return strings.Join(octets, "."), true
}

func resolvePowerShell() string {
	for _, candidate := range []string{"powershell.exe", "powershell", "pwsh.exe", "pwsh"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	return ""
}

func windowsDefaultRouteOutput() (string, error) {
	powershell := resolvePowerShell()
	if powershell == "" {
		return "", exec.ErrNotFound
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	command := exec.CommandContext(ctx, powershell, "-NoProfile", "-Command", "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1 NextHop,InterfaceAlias,InterfaceIndex | ConvertTo-Json -Depth 2")
	output, err := command.Output()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func windowsNeighborOutput() (string, error) {
	powershell := resolvePowerShell()
	if powershell == "" {
		return "", exec.ErrNotFound
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	command := exec.CommandContext(ctx, powershell, "-NoProfile", "-Command", "Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,State | ConvertTo-Json -Depth 2")
	output, err := command.Output()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func arpAOutput() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), localCommandTimeout)
	defer cancel()

	return boundedCommandOutput(ctx, arpExecutablePath(runtime.GOOS), "-a")
}

func darwinDefaultRouteOutput() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), localCommandTimeout)
	defer cancel()

	return boundedCommandOutput(ctx, routeExecutablePath(runtime.GOOS), "-n", "get", "default")
}

func arpExecutablePath(goos string) string {
	if goos == "darwin" {
		return darwinARPPath
	}
	return "arp"
}

func routeExecutablePath(goos string) string {
	if goos == "darwin" {
		return darwinRoutePath
	}
	return "route"
}

func boundedCommandOutput(ctx context.Context, executable string, args ...string) (string, error) {
	command := newLocalCommand(ctx, executable, args...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := command.Start(); err != nil {
		return "", err
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, localCommandMaxBytes+1))
	if ctx.Err() != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return "", ctx.Err()
	}
	if readErr != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return "", readErr
	}
	if len(data) > localCommandMaxBytes {
		_ = command.Process.Kill()
		_ = command.Wait()
		return "", errCommandOutputTooLarge
	}
	waitErr := command.Wait()
	if waitErr != nil {
		return "", waitErr
	}
	return string(data), nil
}
