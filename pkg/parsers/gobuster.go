package parsers

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type GobusterResult struct {
	Results []GobusterFinding `json:"results,omitempty"`
}

type GobusterFinding struct {
	Type             string `json:"type,omitempty"`
	Host             string `json:"host,omitempty"`
	URL              string `json:"url,omitempty"`
	URI              string `json:"uri,omitempty"`
	Path             string `json:"path,omitempty"`
	Status           int    `json:"status,omitempty"`
	ContentLength    int    `json:"content_length,omitempty"`
	Words            int    `json:"words,omitempty"`
	Lines            int    `json:"lines,omitempty"`
	RedirectLocation string `json:"redirect_location,omitempty"`
	Method           string `json:"method,omitempty"`
	Input            string `json:"input,omitempty"`
	Timestamp        string `json:"timestamp,omitempty"`
}

type GobusterStandardParser struct{}

func (p GobusterStandardParser) Name() string {
	return "gobuster-standard"
}

func (p GobusterStandardParser) IsCompatible(content string) bool {
	return len(parseGobusterStandard(content)) > 0
}

func (p GobusterStandardParser) Parse(content string) (interface{}, error) {
	results := parseGobusterStandard(content)
	if len(results) == 0 {
		return GobusterResult{}, errors.New("no gobuster findings found")
	}
	return GobusterResult{Results: results}, nil
}

func parseGobusterStandard(content string) []GobusterFinding {
	lines := strings.Split(content, "\n")
	findings := make([]GobusterFinding, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = strings.TrimPrefix(line, "Found: ")

		matches := gobusterStandardLineRegexp.FindStringSubmatch(line)
		if len(matches) == 0 {
			continue
		}

		path := matches[1]
		status, _ := strconv.Atoi(matches[2])
		size, _ := strconv.Atoi(matches[3])
		redirect := strings.TrimSpace(matches[4])

		finding := GobusterFinding{
			Path:          path,
			Status:        status,
			ContentLength: size,
		}
		if redirect != "" {
			finding.RedirectLocation = redirect
		}
		if u, err := url.Parse(path); err == nil && u.Scheme != "" && u.Host != "" {
			finding.URL = path
			finding.Host = u.Host
		}
		findings = append(findings, finding)
	}
	return findings
}

var gobusterStandardLineRegexp = regexp.MustCompile(`^(?:Found:\s*)?(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\](?:\s+\[(?:-->|Redirect:)\s*([^\]]+)\])?`)
