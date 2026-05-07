package parsers

import (
	"encoding/xml"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type NmapResult struct {
	Scanner          string         `json:"scanner,omitempty"`
	Args             string         `json:"args,omitempty"`
	Start            string         `json:"start,omitempty"`
	StartString      string         `json:"start_string,omitempty"`
	Version          string         `json:"version,omitempty"`
	XMLOutputVersion string         `json:"xml_output_version,omitempty"`
	ScanInfo         []NmapScanInfo `json:"scan_info,omitempty"`
	Hosts            []NmapHost     `json:"hosts,omitempty"`
	RunStats         NmapRunStats   `json:"run_stats,omitempty,omitzero"`
}

type NmapScanInfo struct {
	Type        string `json:"type,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	NumServices int    `json:"num_services,omitempty"`
	Services    string `json:"services,omitempty"`
}

type NmapHost struct {
	IP          string           `json:"ip,omitempty"`
	Hostname    string           `json:"hostname,omitempty"`
	MacAddress  string           `json:"mac_address,omitempty"`
	StartTime   string           `json:"start_time,omitempty"`
	EndTime     string           `json:"end_time,omitempty"`
	Status      NmapStatus       `json:"status,omitempty,omitzero"`
	Latency     string           `json:"latency,omitempty"`
	Addresses   []NmapAddress    `json:"addresses,omitempty"`
	Hostnames   []NmapHostname   `json:"hostnames,omitempty"`
	Ports       []NmapPort       `json:"ports,omitempty"`
	ExtraPorts  []NmapExtraPorts `json:"extra_ports,omitempty"`
	Scripts     []NmapScript     `json:"scripts,omitempty"`
	OS          NmapOS           `json:"os,omitempty,omitzero"`
	Uptime      NmapUptime       `json:"uptime,omitempty,omitzero"`
	Distance    int              `json:"distance,omitempty"`
	ServiceInfo NmapServiceInfo  `json:"service_info,omitempty,omitzero"`
	Trace       NmapTrace        `json:"trace,omitempty,omitzero"`
	Times       NmapTimes        `json:"times,omitempty,omitzero"`
}

type NmapStatus struct {
	State     string `json:"state,omitempty"`
	Reason    string `json:"reason,omitempty"`
	ReasonTTL string `json:"reason_ttl,omitempty"`
}

type NmapAddress struct {
	Addr     string `json:"addr,omitempty"`
	AddrType string `json:"addr_type,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
}

type NmapHostname struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

type NmapExtraPorts struct {
	State   string            `json:"state,omitempty"`
	Count   int               `json:"count,omitempty"`
	Reasons []NmapExtraReason `json:"reasons,omitempty"`
}

type NmapExtraReason struct {
	Reason string `json:"reason,omitempty"`
	Count  int    `json:"count,omitempty"`
}

type NmapPort struct {
	ID       int          `json:"id,omitempty"`
	Protocol string       `json:"protocol,omitempty"`
	State    NmapState    `json:"state,omitempty"`
	Service  NmapService  `json:"service,omitempty"`
	Scripts  []NmapScript `json:"scripts,omitempty"`
}

type NmapState struct {
	State     string `json:"state,omitempty"`
	Reason    string `json:"reason,omitempty"`
	ReasonTTL string `json:"reason_ttl,omitempty"`
}

type NmapService struct {
	Name       string   `json:"name,omitempty"`
	Product    string   `json:"product,omitempty"`
	Version    string   `json:"version,omitempty"`
	ExtraInfo  string   `json:"extra_info,omitempty"`
	OSType     string   `json:"os_type,omitempty"`
	DeviceType string   `json:"device_type,omitempty"`
	Method     string   `json:"method,omitempty"`
	Confidence int      `json:"confidence,omitempty"`
	CPEs       []string `json:"cpes,omitempty"`
}

type NmapScript struct {
	ID       string              `json:"id,omitempty"`
	Output   string              `json:"output,omitempty"`
	Elements []NmapScriptElement `json:"elements,omitempty"`
	Tables   []NmapScriptTable   `json:"tables,omitempty"`
}

type NmapScriptElement struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

type NmapScriptTable struct {
	Key      string              `json:"key,omitempty"`
	Elements []NmapScriptElement `json:"elements,omitempty"`
	Tables   []NmapScriptTable   `json:"tables,omitempty"`
}

type NmapOS struct {
	DeviceType        string         `json:"device_type,omitempty"`
	Running           string         `json:"running,omitempty"`
	CPEs              []string       `json:"cpes,omitempty"`
	Matches           []NmapOSMatch  `json:"matches,omitempty"`
	PortsUsed         []NmapPortUsed `json:"ports_used,omitempty"`
	NoExactMatch      bool           `json:"no_exact_match,omitempty"`
	NoExactMatchNotes string         `json:"no_exact_match_notes,omitempty"`
}

type NmapOSMatch struct {
	Name     string        `json:"name,omitempty"`
	Accuracy int           `json:"accuracy,omitempty"`
	Line     string        `json:"line,omitempty"`
	Classes  []NmapOSClass `json:"classes,omitempty"`
}

type NmapOSClass struct {
	Type     string   `json:"type,omitempty"`
	Vendor   string   `json:"vendor,omitempty"`
	Family   string   `json:"family,omitempty"`
	Gen      string   `json:"gen,omitempty"`
	Accuracy int      `json:"accuracy,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`
}

type NmapPortUsed struct {
	State    string `json:"state,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	ID       int    `json:"id,omitempty"`
}

type NmapUptime struct {
	Seconds  int    `json:"seconds,omitempty"`
	LastBoot string `json:"last_boot,omitempty"`
	Guess    string `json:"guess,omitempty"`
}

type NmapServiceInfo struct {
	OS   string   `json:"os,omitempty"`
	CPEs []string `json:"cpes,omitempty"`
	Raw  string   `json:"raw,omitempty"`
}

type NmapTrace struct {
	Port     int       `json:"port,omitempty"`
	Protocol string    `json:"protocol,omitempty"`
	Hops     []NmapHop `json:"hops,omitempty"`
}

type NmapHop struct {
	TTL      int    `json:"ttl,omitempty"`
	RTT      string `json:"rtt,omitempty"`
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

type NmapTimes struct {
	SRTT   string `json:"srtt,omitempty"`
	RTTVar string `json:"rtt_var,omitempty"`
	To     string `json:"to,omitempty"`
}

type NmapRunStats struct {
	FinishedTime       string  `json:"finished_time,omitempty"`
	FinishedTimeString string  `json:"finished_time_string,omitempty"`
	Elapsed            float64 `json:"elapsed,omitempty"`
	Summary            string  `json:"summary,omitempty"`
	Exit               string  `json:"exit,omitempty"`
	HostsUp            int     `json:"hosts_up,omitempty"`
	HostsDown          int     `json:"hosts_down,omitempty"`
	HostsTotal         int     `json:"hosts_total,omitempty"`
}

type NmapScanResult = NmapResult
type Host = NmapHost
type Address = NmapAddress
type Port = NmapPort
type State = NmapState
type Service = NmapService
type GrepableNmapResult = NmapResult
type GrepableHost = NmapHost
type StandardNmapResult = NmapResult
type StandardNmapHost = NmapHost
type StandardNmapPort = NmapPort

type NmapXMLParser struct{}

func (p NmapXMLParser) Name() string {
	return "nmap-xml"
}

func (p NmapXMLParser) IsCompatible(content string) bool {
	return strings.Contains(content, "<nmaprun")
}

func (p NmapXMLParser) Parse(content string) (interface{}, error) {
	var raw xmlNmapRun
	if err := xml.Unmarshal([]byte(content), &raw); err != nil {
		return nil, err
	}

	return raw.toResult(), nil
}

type NmapGrepableParser struct{}

func (p NmapGrepableParser) Name() string {
	return "nmap-grepable"
}

func (p NmapGrepableParser) IsCompatible(content string) bool {
	return grepableHostLineRegex.MatchString(content)
}

func (p NmapGrepableParser) Parse(content string) (interface{}, error) {
	return parseGrepableNmap(content), nil
}

type StandardNmapParser struct{}

func (p StandardNmapParser) Name() string {
	return "nmap-standard"
}

func (p StandardNmapParser) IsCompatible(content string) bool {
	return strings.Contains(content, "Nmap scan report for")
}

func (p StandardNmapParser) Parse(content string) (interface{}, error) {
	return parseStandardNmap(content), nil
}

func ExtractOpenPorts(scanResult NmapResult) []NmapPort {
	var openPorts []NmapPort
	for _, host := range scanResult.Hosts {
		for _, port := range host.Ports {
			if port.State.State == "open" {
				openPorts = append(openPorts, port)
			}
		}
	}
	return openPorts
}

type xmlNmapRun struct {
	Scanner          string        `xml:"scanner,attr"`
	Args             string        `xml:"args,attr"`
	Start            string        `xml:"start,attr"`
	StartString      string        `xml:"startstr,attr"`
	Version          string        `xml:"version,attr"`
	XMLOutputVersion string        `xml:"xmloutputversion,attr"`
	ScanInfo         []xmlScanInfo `xml:"scaninfo"`
	Hosts            []xmlHost     `xml:"host"`
	RunStats         xmlRunStats   `xml:"runstats"`
}

type xmlScanInfo struct {
	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices int    `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
}

type xmlHost struct {
	StartTime  string          `xml:"starttime,attr"`
	EndTime    string          `xml:"endtime,attr"`
	Status     xmlStatus       `xml:"status"`
	Addresses  []xmlAddress    `xml:"address"`
	Hostnames  []xmlHostname   `xml:"hostnames>hostname"`
	Ports      []xmlPort       `xml:"ports>port"`
	ExtraPorts []xmlExtraPorts `xml:"ports>extraports"`
	HostScript []xmlScript     `xml:"hostscript>script"`
	OS         xmlOS           `xml:"os"`
	Uptime     xmlUptime       `xml:"uptime"`
	Distance   xmlDistance     `xml:"distance"`
	Trace      xmlTrace        `xml:"trace"`
	Times      xmlTimes        `xml:"times"`
}

type xmlStatus struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
}

type xmlAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type xmlHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type xmlExtraPorts struct {
	State   string           `xml:"state,attr"`
	Count   int              `xml:"count,attr"`
	Reasons []xmlExtraReason `xml:"extrareasons"`
}

type xmlExtraReason struct {
	Reason string `xml:"reason,attr"`
	Count  int    `xml:"count,attr"`
}

type xmlPort struct {
	ID       int         `xml:"portid,attr"`
	Protocol string      `xml:"protocol,attr"`
	State    xmlState    `xml:"state"`
	Service  xmlService  `xml:"service"`
	Scripts  []xmlScript `xml:"script"`
}

type xmlState struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
}

type xmlService struct {
	Name       string   `xml:"name,attr"`
	Product    string   `xml:"product,attr"`
	Version    string   `xml:"version,attr"`
	ExtraInfo  string   `xml:"extrainfo,attr"`
	OSType     string   `xml:"ostype,attr"`
	DeviceType string   `xml:"devicetype,attr"`
	Method     string   `xml:"method,attr"`
	Confidence int      `xml:"conf,attr"`
	CPEs       []string `xml:"cpe"`
}

type xmlScript struct {
	ID       string             `xml:"id,attr"`
	Output   string             `xml:"output,attr"`
	Elements []xmlScriptElement `xml:"elem"`
	Tables   []xmlScriptTable   `xml:"table"`
}

type xmlScriptElement struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type xmlScriptTable struct {
	Key      string             `xml:"key,attr"`
	Elements []xmlScriptElement `xml:"elem"`
	Tables   []xmlScriptTable   `xml:"table"`
}

type xmlOS struct {
	PortsUsed []xmlPortUsed `xml:"portused"`
	Matches   []xmlOSMatch  `xml:"osmatch"`
	Classes   []xmlOSClass  `xml:"osclass"`
}

type xmlOSMatch struct {
	Name     string       `xml:"name,attr"`
	Accuracy int          `xml:"accuracy,attr"`
	Line     string       `xml:"line,attr"`
	Classes  []xmlOSClass `xml:"osclass"`
}

type xmlOSClass struct {
	Type     string   `xml:"type,attr"`
	Vendor   string   `xml:"vendor,attr"`
	Family   string   `xml:"osfamily,attr"`
	Gen      string   `xml:"osgen,attr"`
	Accuracy int      `xml:"accuracy,attr"`
	CPEs     []string `xml:"cpe"`
}

type xmlPortUsed struct {
	State    string `xml:"state,attr"`
	Protocol string `xml:"proto,attr"`
	ID       int    `xml:"portid,attr"`
}

type xmlUptime struct {
	Seconds  int    `xml:"seconds,attr"`
	LastBoot string `xml:"lastboot,attr"`
}

type xmlDistance struct {
	Value int `xml:"value,attr"`
}

type xmlTrace struct {
	Port     int      `xml:"port,attr"`
	Protocol string   `xml:"proto,attr"`
	Hops     []xmlHop `xml:"hop"`
}

type xmlHop struct {
	TTL      int    `xml:"ttl,attr"`
	RTT      string `xml:"rtt,attr"`
	IP       string `xml:"ipaddr,attr"`
	Hostname string `xml:"host,attr"`
}

type xmlTimes struct {
	SRTT   string `xml:"srtt,attr"`
	RTTVar string `xml:"rttvar,attr"`
	To     string `xml:"to,attr"`
}

type xmlRunStats struct {
	Finished xmlFinished `xml:"finished"`
	Hosts    xmlHosts    `xml:"hosts"`
}

type xmlFinished struct {
	Time       string  `xml:"time,attr"`
	TimeString string  `xml:"timestr,attr"`
	Elapsed    float64 `xml:"elapsed,attr"`
	Summary    string  `xml:"summary,attr"`
	Exit       string  `xml:"exit,attr"`
}

type xmlHosts struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

func (r xmlNmapRun) toResult() NmapResult {
	result := NmapResult{
		Scanner:          r.Scanner,
		Args:             r.Args,
		Start:            r.Start,
		StartString:      r.StartString,
		Version:          r.Version,
		XMLOutputVersion: r.XMLOutputVersion,
		ScanInfo:         make([]NmapScanInfo, 0, len(r.ScanInfo)),
		Hosts:            make([]NmapHost, 0, len(r.Hosts)),
		RunStats: NmapRunStats{
			FinishedTime:       r.RunStats.Finished.Time,
			FinishedTimeString: r.RunStats.Finished.TimeString,
			Elapsed:            r.RunStats.Finished.Elapsed,
			Summary:            strings.Join(strings.Fields(r.RunStats.Finished.Summary), " "),
			Exit:               r.RunStats.Finished.Exit,
			HostsUp:            r.RunStats.Hosts.Up,
			HostsDown:          r.RunStats.Hosts.Down,
			HostsTotal:         r.RunStats.Hosts.Total,
		},
	}

	for _, scanInfo := range r.ScanInfo {
		result.ScanInfo = append(result.ScanInfo, NmapScanInfo(scanInfo))
	}

	for _, host := range r.Hosts {
		result.Hosts = append(result.Hosts, host.toHost())
	}

	return result
}

func (h xmlHost) toHost() NmapHost {
	host := NmapHost{
		StartTime: h.StartTime,
		EndTime:   h.EndTime,
		Status: NmapStatus{
			State:     h.Status.State,
			Reason:    h.Status.Reason,
			ReasonTTL: h.Status.ReasonTTL,
		},
		Addresses:  make([]NmapAddress, 0, len(h.Addresses)),
		Hostnames:  make([]NmapHostname, 0, len(h.Hostnames)),
		Ports:      make([]NmapPort, 0, len(h.Ports)),
		ExtraPorts: make([]NmapExtraPorts, 0, len(h.ExtraPorts)),
		Scripts:    xmlScriptsToScripts(h.HostScript),
		Distance:   h.Distance.Value,
		Uptime: NmapUptime{
			Seconds:  h.Uptime.Seconds,
			LastBoot: h.Uptime.LastBoot,
		},
		Times: NmapTimes{
			SRTT:   h.Times.SRTT,
			RTTVar: h.Times.RTTVar,
			To:     h.Times.To,
		},
		Trace: NmapTrace{
			Port:     h.Trace.Port,
			Protocol: h.Trace.Protocol,
			Hops:     make([]NmapHop, 0, len(h.Trace.Hops)),
		},
	}

	for _, address := range h.Addresses {
		host.Addresses = append(host.Addresses, NmapAddress(address))
		switch address.AddrType {
		case "ipv4", "ipv6":
			if host.IP == "" {
				host.IP = address.Addr
			}
		case "mac":
			host.MacAddress = address.Addr
		}
	}

	for _, hostname := range h.Hostnames {
		host.Hostnames = append(host.Hostnames, NmapHostname(hostname))
		if host.Hostname == "" {
			host.Hostname = hostname.Name
		}
	}

	for _, extraPorts := range h.ExtraPorts {
		host.ExtraPorts = append(host.ExtraPorts, extraPorts.toExtraPorts())
	}

	for _, port := range h.Ports {
		host.Ports = append(host.Ports, port.toPort())
	}
	host.OS = h.OS.toOS()
	for _, hop := range h.Trace.Hops {
		host.Trace.Hops = append(host.Trace.Hops, NmapHop(hop))
	}

	return host
}

func (e xmlExtraPorts) toExtraPorts() NmapExtraPorts {
	extraPorts := NmapExtraPorts{
		State:   e.State,
		Count:   e.Count,
		Reasons: make([]NmapExtraReason, 0, len(e.Reasons)),
	}
	for _, reason := range e.Reasons {
		extraPorts.Reasons = append(extraPorts.Reasons, NmapExtraReason(reason))
	}
	return extraPorts
}

func (p xmlPort) toPort() NmapPort {
	return NmapPort{
		ID:       p.ID,
		Protocol: p.Protocol,
		State: NmapState{
			State:     p.State.State,
			Reason:    p.State.Reason,
			ReasonTTL: p.State.ReasonTTL,
		},
		Service: NmapService{
			Name:       p.Service.Name,
			Product:    p.Service.Product,
			Version:    p.Service.Version,
			ExtraInfo:  p.Service.ExtraInfo,
			OSType:     p.Service.OSType,
			DeviceType: p.Service.DeviceType,
			Method:     p.Service.Method,
			Confidence: p.Service.Confidence,
			CPEs:       compactStrings(p.Service.CPEs),
		},
		Scripts: xmlScriptsToScripts(p.Scripts),
	}
}

func (o xmlOS) toOS() NmapOS {
	osInfo := NmapOS{
		PortsUsed: make([]NmapPortUsed, 0, len(o.PortsUsed)),
		Matches:   make([]NmapOSMatch, 0, len(o.Matches)+len(o.Classes)),
	}

	for _, port := range o.PortsUsed {
		osInfo.PortsUsed = append(osInfo.PortsUsed, NmapPortUsed(port))
	}
	for _, match := range o.Matches {
		osInfo.Matches = append(osInfo.Matches, match.toOSMatch())
	}
	for _, class := range o.Classes {
		osInfo.Matches = append(osInfo.Matches, NmapOSMatch{
			Accuracy: class.Accuracy,
			Classes:  []NmapOSClass{class.toOSClass()},
		})
	}

	return osInfo
}

func (m xmlOSMatch) toOSMatch() NmapOSMatch {
	match := NmapOSMatch{
		Name:     m.Name,
		Accuracy: m.Accuracy,
		Line:     m.Line,
		Classes:  make([]NmapOSClass, 0, len(m.Classes)),
	}
	for _, class := range m.Classes {
		match.Classes = append(match.Classes, class.toOSClass())
	}
	return match
}

func (c xmlOSClass) toOSClass() NmapOSClass {
	return NmapOSClass{
		Type:     c.Type,
		Vendor:   c.Vendor,
		Family:   c.Family,
		Gen:      c.Gen,
		Accuracy: c.Accuracy,
		CPEs:     compactStrings(c.CPEs),
	}
}

func xmlScriptsToScripts(scripts []xmlScript) []NmapScript {
	result := make([]NmapScript, 0, len(scripts))
	for _, script := range scripts {
		result = append(result, script.toScript())
	}
	return result
}

func (s xmlScript) toScript() NmapScript {
	script := NmapScript{
		ID:       s.ID,
		Output:   strings.TrimSpace(s.Output),
		Elements: make([]NmapScriptElement, 0, len(s.Elements)),
		Tables:   make([]NmapScriptTable, 0, len(s.Tables)),
	}
	for _, element := range s.Elements {
		script.Elements = append(script.Elements, NmapScriptElement{
			Key:   element.Key,
			Value: strings.TrimSpace(element.Value),
		})
	}
	for _, table := range s.Tables {
		script.Tables = append(script.Tables, table.toScriptTable())
	}
	return script
}

func (t xmlScriptTable) toScriptTable() NmapScriptTable {
	table := NmapScriptTable{
		Key:      t.Key,
		Elements: make([]NmapScriptElement, 0, len(t.Elements)),
		Tables:   make([]NmapScriptTable, 0, len(t.Tables)),
	}
	for _, element := range t.Elements {
		table.Elements = append(table.Elements, NmapScriptElement{
			Key:   element.Key,
			Value: strings.TrimSpace(element.Value),
		})
	}
	for _, child := range t.Tables {
		table.Tables = append(table.Tables, child.toScriptTable())
	}
	return table
}

var (
	startLineRegex          = regexp.MustCompile(`^Starting Nmap\s+([^\s]+).*\sat\s+(.+)$`)
	hostLineRegex           = regexp.MustCompile(`^Nmap scan report for (.+)$`)
	hostUpRegex             = regexp.MustCompile(`^Host is (\w+)(?: \(([^)]*)\))?\.?`)
	notShownRegex           = regexp.MustCompile(`(\d+)\s+([A-Za-z|]+)\s+ports?`)
	allPortsRegex           = regexp.MustCompile(`^All\s+(\d+)\s+scanned ports on .+ are ([A-Za-z|]+)$`)
	portLineRegex           = regexp.MustCompile(`^(\d+)/(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$`)
	macRegex                = regexp.MustCompile(`^MAC Address:\s+([0-9A-Fa-f:.]+)(?:\s+\((.+)\))?`)
	distanceRegex           = regexp.MustCompile(`^Network Distance:\s+(\d+)\s+hops?`)
	runStatsRegex           = regexp.MustCompile(`^Nmap done:\s+(\d+)\s+IP addresses? \((\d+)\s+hosts? up\) scanned in ([0-9.]+)\s+seconds`)
	osGuessRegex            = regexp.MustCompile(`(.+?) \((\d+)%\)`)
	traceHeaderRegex        = regexp.MustCompile(`^TRACEROUTE \(using port (\d+)/(\w+)\)`)
	traceHopRegex           = regexp.MustCompile(`^(\d+)\s+([0-9.]+)\s+ms\s+(.+)$`)
	grepableHostLineRegex   = regexp.MustCompile(`(?m)^Host:\s+(\S+)\s+\((.*?)\)(.*)$`)
	grepableIgnoredRegex    = regexp.MustCompile(`Ignored State:\s+(\S+)\s+\((\d+)\)`)
	serviceInfoFieldRegex   = regexp.MustCompile(`([A-Za-z ]+):\s*([^;]+)`)
	otherAddressesLineRegex = regexp.MustCompile(`^Other addresses for .+ \(not scanned\):\s+(.+)$`)
)

func parseStandardNmap(content string) NmapResult {
	result := NmapResult{Scanner: "nmap"}
	var currentHost *NmapHost
	var currentPort *NmapPort
	var currentScript *NmapScript
	inTrace := false

	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if match := startLineRegex.FindStringSubmatch(trimmed); match != nil {
			result.Version = match[1]
			result.StartString = match[2]
			continue
		}

		if match := hostLineRegex.FindStringSubmatch(trimmed); match != nil {
			result.Hosts = append(result.Hosts, newTextHost(match[1]))
			currentHost = &result.Hosts[len(result.Hosts)-1]
			currentPort = nil
			currentScript = nil
			inTrace = false
			continue
		}

		if currentHost == nil {
			continue
		}

		if strings.HasPrefix(trimmed, "|") {
			currentScript = appendScriptLine(currentPort, currentScript, trimmed)
			continue
		}
		currentScript = nil

		if match := hostUpRegex.FindStringSubmatch(trimmed); match != nil {
			currentHost.Status.State = match[1]
			currentHost.Latency = strings.TrimSpace(match[2])
			if notShownIndex := strings.Index(trimmed, "Not shown:"); notShownIndex >= 0 {
				currentHost.ExtraPorts = append(currentHost.ExtraPorts, parseNotShownExtraPorts(trimmed[notShownIndex:])...)
			}
			continue
		}

		if match := otherAddressesLineRegex.FindStringSubmatch(trimmed); match != nil {
			for _, address := range strings.Fields(match[1]) {
				currentHost.Addresses = appendAddress(currentHost.Addresses, address, detectAddressType(address), "")
			}
			continue
		}

		if strings.HasPrefix(trimmed, "Not shown:") {
			currentHost.ExtraPorts = append(currentHost.ExtraPorts, parseNotShownExtraPorts(trimmed)...)
			continue
		}

		if match := allPortsRegex.FindStringSubmatch(trimmed); match != nil {
			currentHost.ExtraPorts = append(currentHost.ExtraPorts, NmapExtraPorts{
				Count: atoi(match[1]),
				State: match[2],
			})
			continue
		}

		if match := portLineRegex.FindStringSubmatch(trimmed); match != nil {
			currentHost.Ports = append(currentHost.Ports, NmapPort{
				ID:       atoi(match[1]),
				Protocol: match[2],
				State:    NmapState{State: match[3]},
				Service: NmapService{
					Name:      match[4],
					ExtraInfo: strings.TrimSpace(match[5]),
				},
			})
			currentPort = &currentHost.Ports[len(currentHost.Ports)-1]
			continue
		}

		if match := macRegex.FindStringSubmatch(trimmed); match != nil {
			currentHost.MacAddress = match[1]
			currentHost.Addresses = appendAddress(currentHost.Addresses, match[1], "mac", strings.TrimSpace(match[2]))
			continue
		}

		if strings.HasPrefix(trimmed, "Device type:") {
			currentHost.OS.DeviceType = strings.TrimSpace(strings.TrimPrefix(trimmed, "Device type:"))
			continue
		}

		if strings.HasPrefix(trimmed, "Running") {
			_, value, ok := strings.Cut(trimmed, ":")
			if ok {
				currentHost.OS.Running = strings.TrimSpace(value)
			}
			continue
		}

		if strings.HasPrefix(trimmed, "OS CPE:") {
			currentHost.OS.CPEs = compactStrings(strings.Fields(strings.TrimSpace(strings.TrimPrefix(trimmed, "OS CPE:"))))
			continue
		}

		if strings.HasPrefix(trimmed, "Aggressive OS guesses:") {
			currentHost.OS.Matches = parseOSGuesses(strings.TrimSpace(strings.TrimPrefix(trimmed, "Aggressive OS guesses:")))
			continue
		}

		if strings.HasPrefix(trimmed, "No exact OS matches") {
			currentHost.OS.NoExactMatch = true
			currentHost.OS.NoExactMatchNotes = trimmed
			continue
		}

		if strings.HasPrefix(trimmed, "Uptime guess:") {
			currentHost.Uptime.Guess = strings.TrimSpace(strings.TrimPrefix(trimmed, "Uptime guess:"))
			continue
		}

		if match := distanceRegex.FindStringSubmatch(trimmed); match != nil {
			currentHost.Distance = atoi(match[1])
			continue
		}

		if strings.HasPrefix(trimmed, "Service Info:") {
			currentHost.ServiceInfo = parseServiceInfo(strings.TrimSpace(strings.TrimPrefix(trimmed, "Service Info:")))
			continue
		}

		if match := traceHeaderRegex.FindStringSubmatch(trimmed); match != nil {
			currentHost.Trace.Port = atoi(match[1])
			currentHost.Trace.Protocol = match[2]
			inTrace = true
			continue
		}

		if inTrace {
			if strings.HasPrefix(trimmed, "HOP ") {
				continue
			}
			if match := traceHopRegex.FindStringSubmatch(trimmed); match != nil {
				hostname, ip := parseTarget(match[3])
				currentHost.Trace.Hops = append(currentHost.Trace.Hops, NmapHop{
					TTL:      atoi(match[1]),
					RTT:      match[2],
					IP:       ip,
					Hostname: hostname,
				})
				continue
			}
			inTrace = false
		}

		if match := runStatsRegex.FindStringSubmatch(trimmed); match != nil {
			result.RunStats.HostsTotal = atoi(match[1])
			result.RunStats.HostsUp = atoi(match[2])
			result.RunStats.Elapsed = atof(match[3])
			result.RunStats.Summary = trimmed
		}
	}

	return result
}

func newTextHost(target string) NmapHost {
	hostname, ip := parseTarget(target)
	host := NmapHost{
		IP:       ip,
		Hostname: hostname,
	}
	if ip != "" {
		host.Addresses = appendAddress(host.Addresses, ip, detectAddressType(ip), "")
	}
	if hostname != "" {
		host.Hostnames = append(host.Hostnames, NmapHostname{Name: hostname})
	}
	return host
}

func parseTarget(target string) (hostname string, ip string) {
	target = strings.TrimSpace(target)
	if strings.HasSuffix(target, ")") {
		if open := strings.LastIndex(target, " ("); open > 0 {
			hostname = strings.TrimSpace(target[:open])
			ip = strings.TrimSuffix(target[open+2:], ")")
			return hostname, ip
		}
	}
	if net.ParseIP(target) != nil {
		return "", target
	}
	return target, ""
}

func appendScriptLine(port *NmapPort, current *NmapScript, line string) *NmapScript {
	if port == nil {
		return current
	}

	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimPrefix(trimmed, "|_")
	trimmed = strings.TrimPrefix(trimmed, "|")
	trimmed = strings.TrimSpace(trimmed)

	if trimmed == "" {
		return current
	}

	if id, output, ok := strings.Cut(trimmed, ":"); ok && strings.TrimSpace(id) != "" && !strings.Contains(id, " ") {
		port.Scripts = append(port.Scripts, NmapScript{
			ID:     strings.TrimSpace(id),
			Output: strings.TrimSpace(output),
		})
		return &port.Scripts[len(port.Scripts)-1]
	}

	if current != nil {
		if current.Output == "" {
			current.Output = trimmed
		} else {
			current.Output += "\n" + trimmed
		}
	}
	return current
}

func parseNotShownExtraPorts(line string) []NmapExtraPorts {
	matches := notShownRegex.FindAllStringSubmatch(line, -1)
	extraPorts := make([]NmapExtraPorts, 0, len(matches))
	for _, match := range matches {
		extraPorts = append(extraPorts, NmapExtraPorts{
			Count: atoi(match[1]),
			State: match[2],
		})
	}
	return extraPorts
}

func parseOSGuesses(raw string) []NmapOSMatch {
	parts := splitCommaList(raw)
	matches := make([]NmapOSMatch, 0, len(parts))
	for _, part := range parts {
		match := osGuessRegex.FindStringSubmatch(part)
		if match == nil {
			continue
		}
		matches = append(matches, NmapOSMatch{
			Name:     strings.TrimSpace(match[1]),
			Accuracy: atoi(match[2]),
		})
	}
	return matches
}

func parseServiceInfo(raw string) NmapServiceInfo {
	info := NmapServiceInfo{Raw: raw}
	for _, match := range serviceInfoFieldRegex.FindAllStringSubmatch(raw, -1) {
		key := strings.TrimSpace(match[1])
		value := strings.TrimSpace(match[2])
		switch key {
		case "OS":
			info.OS = value
		case "CPE":
			info.CPEs = append(info.CPEs, strings.Fields(value)...)
		}
	}
	info.CPEs = compactStrings(info.CPEs)
	return info
}

func parseGrepableNmap(content string) NmapResult {
	result := NmapResult{Scanner: "nmap"}
	hostIndexes := map[string]int{}

	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		match := grepableHostLineRegex.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		ip := match[1]
		hostIndex, ok := hostIndexes[ip]
		if !ok {
			hostname := strings.TrimSpace(match[2])
			host := NmapHost{
				IP:        ip,
				Hostname:  hostname,
				Addresses: []NmapAddress{{Addr: ip, AddrType: detectAddressType(ip)}},
			}
			if hostname != "" {
				host.Hostnames = append(host.Hostnames, NmapHostname{Name: hostname})
			}
			result.Hosts = append(result.Hosts, host)
			hostIndex = len(result.Hosts) - 1
			hostIndexes[ip] = hostIndex
		}

		host := &result.Hosts[hostIndex]
		for _, field := range strings.Split(match[3], "\t") {
			parseGrepableField(host, field)
		}
	}

	return result
}

func parseGrepableField(host *NmapHost, field string) {
	field = strings.TrimSpace(field)
	if field == "" {
		return
	}

	if match := grepableIgnoredRegex.FindStringSubmatch(field); match != nil {
		host.ExtraPorts = append(host.ExtraPorts, NmapExtraPorts{
			State: match[1],
			Count: atoi(match[2]),
		})
	}

	switch {
	case strings.HasPrefix(field, "Status:"):
		host.Status.State = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(field, "Status:")))
	case strings.HasPrefix(field, "Ports:"):
		host.Ports = append(host.Ports, parseGrepablePorts(field)...)
	}
}

func parseGrepablePorts(field string) []NmapPort {
	rawPorts := strings.TrimSpace(strings.TrimPrefix(field, "Ports:"))
	if ignoredIndex := strings.Index(rawPorts, "Ignored State:"); ignoredIndex >= 0 {
		rawPorts = rawPorts[:ignoredIndex]
	}

	entries := strings.Split(rawPorts, ",")
	ports := make([]NmapPort, 0, len(entries))
	for _, entry := range entries {
		parts := strings.Split(strings.TrimSpace(entry), "/")
		if len(parts) < 5 {
			continue
		}
		port := NmapPort{
			ID:       atoi(parts[0]),
			Protocol: parts[2],
			State:    NmapState{State: parts[1]},
			Service:  NmapService{Name: parts[4]},
		}
		if len(parts) > 6 {
			port.Service.ExtraInfo = strings.TrimSpace(strings.Join(parts[6:], "/"))
		}
		ports = append(ports, port)
	}
	return ports
}

func appendAddress(addresses []NmapAddress, addr string, addrType string, vendor string) []NmapAddress {
	for _, address := range addresses {
		if address.Addr == addr && address.AddrType == addrType {
			return addresses
		}
	}
	return append(addresses, NmapAddress{
		Addr:     addr,
		AddrType: addrType,
		Vendor:   vendor,
	})
}

func detectAddressType(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func splitCommaList(raw string) []string {
	var parts []string
	var current strings.Builder
	depth := 0

	for _, r := range raw {
		switch r {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(current.String()))
				current.Reset()
				continue
			}
		}
		current.WriteRune(r)
	}

	if strings.TrimSpace(current.String()) != "" {
		parts = append(parts, strings.TrimSpace(current.String()))
	}
	return parts
}

func compactStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func atoi(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return parsed
}

func atof(value string) float64 {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0
	}
	return parsed
}
