package parsers

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

type SubfinderResult struct {
	Findings []SubfinderFinding `json:"findings,omitempty"`
}

type SubfinderFinding struct {
	Host                string `json:"host,omitempty"`
	Input               string `json:"input,omitempty"`
	Source              string `json:"source,omitempty"`
	WildcardCertificate bool   `json:"wildcard_certificate,omitempty"`
	IP                  string `json:"ip,omitempty"`
}

type SubfinderJSONParser struct{}

func (p SubfinderJSONParser) Name() string {
	return "subfinder-json"
}

func (p SubfinderJSONParser) IsCompatible(content string) bool {
	findings, err := parseSubfinderJSON(content)
	return err == nil && len(findings) > 0
}

func (p SubfinderJSONParser) Parse(content string) (interface{}, error) {
	findings, err := parseSubfinderJSON(content)
	if err != nil {
		return nil, err
	}
	return SubfinderResult{Findings: findings}, nil
}

type SubfinderStandardParser struct{}

func (p SubfinderStandardParser) Name() string {
	return "subfinder-standard"
}

func (p SubfinderStandardParser) IsCompatible(content string) bool {
	return len(parseSubfinderStandard(content)) > 0
}

func (p SubfinderStandardParser) Parse(content string) (interface{}, error) {
	findings := parseSubfinderStandard(content)
	if len(findings) == 0 {
		return SubfinderResult{}, errors.New("no subfinder findings found")
	}
	return SubfinderResult{Findings: findings}, nil
}

var subfinderHostRegexp = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9_-]*\.)+[a-zA-Z0-9_-]+$`)

func parseSubfinderJSON(content string) ([]SubfinderFinding, error) {
	content = strings.TrimSpace(strings.TrimPrefix(content, "\ufeff"))
	if content == "" {
		return nil, errors.New("empty subfinder JSON output")
	}

	var findings []SubfinderFinding
	if strings.HasPrefix(content, "[") {
		if err := json.Unmarshal([]byte(content), &findings); err != nil {
			return nil, err
		}
		if len(findings) == 0 {
			return nil, errors.New("no subfinder JSON findings")
		}
		for _, finding := range findings {
			if finding.Host == "" {
				return nil, errors.New("subfinder JSON finding missing host")
			}
			if !subfinderHostRegexp.MatchString(finding.Host) {
				return nil, errors.New("subfinder JSON finding has invalid host")
			}
		}
		return findings, nil
	}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result SubfinderFinding
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return nil, err
		}
		if result.Host == "" {
			return nil, errors.New("subfinder JSON finding missing host")
		}
		if !subfinderHostRegexp.MatchString(result.Host) {
			return nil, errors.New("subfinder JSON finding has invalid host")
		}
		findings = append(findings, result)
	}

	if len(findings) == 0 {
		return nil, errors.New("no subfinder JSON findings")
	}
	return findings, nil
}

func parseSubfinderStandard(content string) []SubfinderFinding {
	lines := strings.Split(content, "\n")
	findings := make([]SubfinderFinding, 0, len(lines))
	for _, line := range lines {
		host := strings.TrimSpace(line)
		if host == "" {
			continue
		}
		if !subfinderHostRegexp.MatchString(host) {
			return nil
		}
		findings = append(findings, SubfinderFinding{Host: host})
	}
	return findings
}
