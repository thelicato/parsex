package parsers

import (
	"encoding/xml"
	"regexp"
	"strings"
)

type NmapXMLParser struct {
}

// NmapScanResult represents the top-level structure of an Nmap XML output
type NmapScanResult struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

// Host represents each host element in the Nmap output
type Host struct {
	Addresses  []Address `xml:"address"`
	Ports      []Port    `xml:"ports>port"`
	MacAddress string    // Add this field for MAC address
}

// Address represents an address element for a host
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	// Add more fields as necessary
}

// Port represents a port element for a host
type Port struct {
	PortID   int     `xml:"portid,attr"`
	Protocol string  `xml:"protocol,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
	// Add more fields as necessary
}

// State represents the state of a port
type State struct {
	State string `xml:"state,attr"`
	// Add more fields as necessary
}

// Service represents the service running on a port
type Service struct {
	Name string `xml:"name,attr"`
	// Add more fields as necessary
}

func (p NmapXMLParser) Name() string {
	return "nmap XML"
}

func (p NmapXMLParser) IsCompatible(content string) bool {
	return strings.Contains(content, "<nmaprun")
}

// ExtractOpenPorts returns a slice of open ports from the Nmap scan result
func ExtractOpenPorts(scanResult NmapScanResult) []Port {
	var openPorts []Port
	for _, host := range scanResult.Hosts {
		for _, port := range host.Ports {
			if port.State.State == "open" {
				openPorts = append(openPorts, port)
			}
		}
	}
	return openPorts
}

func (p NmapXMLParser) Parse(content string) (interface{}, error) {
	var result NmapScanResult
	err := xml.Unmarshal([]byte(content), &result)
	if err != nil {
		return nil, err
	}
	for _, host := range result.Hosts {
		for _, address := range host.Addresses {
			if address.AddrType == "mac" {
				host.MacAddress = address.Addr
				break
			}
		}
	}

	openPorts := ExtractOpenPorts(result)
	return openPorts, nil
}

type NmapGrepableParser struct{}

type GrepableNmapResult struct {
	Hosts []GrepableHost
}

type GrepableHost struct {
	IP         string
	Hostname   string
	MacAddress string // Add this field for MAC address
	Ports      []string
}

func (p NmapGrepableParser) Name() string {
	return "nmap Grepable"
}

func (p NmapGrepableParser) IsCompatible(content string) bool {
	return strings.Contains(content, "Host:") || strings.HasPrefix(content, "# Nmap")
}

func (p NmapGrepableParser) Parse(content string) (interface{}, error) {
	var result GrepableNmapResult
	var currentHost *GrepableHost

	lines := strings.Split(content, "\n")
	hostRegex := regexp.MustCompile(`Host: (\S+) \((.*?)\)`)                // Matches IP and Hostname
	portRegex := regexp.MustCompile(`Ports: (\d+)/(\w+)/(\w+)/(\w+)/(\S+)`) // Matches Port information
	macRegex := regexp.MustCompile(`MAC Address: ([\dA-Fa-f:.]+) \((.+)\)`) // Matches MAC address

	for _, line := range lines {
		if hostMatch := hostRegex.FindStringSubmatch(line); hostMatch != nil {
			// Process the previous host, if any
			if currentHost != nil {
				result.Hosts = append(result.Hosts, *currentHost)
			}
			// Start a new host
			currentHost = &GrepableHost{
				IP:       hostMatch[1],
				Hostname: hostMatch[2],
			}
			continue
		}

		if currentHost != nil {
			if portMatch := portRegex.FindStringSubmatch(line); portMatch != nil {
				portInfo := portMatch[1] + "/" + portMatch[2] + " (" + portMatch[4] + ")"
				currentHost.Ports = append(currentHost.Ports, portInfo)
			}

			if macMatch := macRegex.FindStringSubmatch(line); macMatch != nil {
				currentHost.MacAddress = macMatch[1]
			}
		}
	}

	// Append the last host if it exists
	if currentHost != nil {
		result.Hosts = append(result.Hosts, *currentHost)
	}

	return result, nil
}

type StandardNmapResult struct {
	Hosts []StandardNmapHost
}

type StandardNmapHost struct {
	IP         string
	MacAddress string // Add this field for MAC address
	Ports      []StandardNmapPort
}

type StandardNmapPort struct {
	Port    string
	Service string
	State   string
}

type StandardNmapParser struct{}

func (p StandardNmapParser) Name() string {
	return "nmap standard"
}

func (p StandardNmapParser) IsCompatible(content string) bool {
	// Implement a check to see if this is a standard Nmap output.
	// This can be tricky as standard output does not have a unique identifier.
	// You might check for common phrases or formats found in standard output.
	return strings.Contains(content, "Nmap scan report for")
}

func (p StandardNmapParser) Parse(content string) (interface{}, error) {
	var result StandardNmapResult
	var currentHost *StandardNmapHost

	lines := strings.Split(content, "\n")
	hostRegex := regexp.MustCompile(`Nmap scan report for (.+)`)
	portRegex := regexp.MustCompile(`(\d+)/(\w+)\s+(\w+)\s+(.+)`)
	macRegex := regexp.MustCompile(`MAC Address: ([\dA-Fa-f:.]+)`)

	for _, line := range lines {
		// Check if the line indicates a new host
		if hostMatch := hostRegex.FindStringSubmatch(line); hostMatch != nil {
			// Found a new host, process the previous host, if any
			if currentHost != nil {
				result.Hosts = append(result.Hosts, *currentHost)
			}
			// Start a new host
			currentHost = &StandardNmapHost{
				IP: hostMatch[1],
			}
			continue
		}

		// Check if the line indicates a port
		if portMatch := portRegex.FindStringSubmatch(line); portMatch != nil {
			if strings.HasPrefix(line, "Discovered open port") {
				// Skip lines that start with "Discovered open port"
				continue
			}

			// Found a port, add it to the current host
			currentHost.Ports = append(currentHost.Ports, StandardNmapPort{
				Port:    portMatch[1],
				State:   portMatch[3],
				Service: portMatch[4],
			})
		}

		if macMatch := macRegex.FindStringSubmatch(line); macMatch != nil {
			if currentHost != nil {
				currentHost.MacAddress = macMatch[1]
			}
		}
	}

	// Append the last host if it exists
	if currentHost != nil {
		result.Hosts = append(result.Hosts, *currentHost)
	}

	return result, nil
}
