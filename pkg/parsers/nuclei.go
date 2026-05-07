package parsers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type NucleiResult struct {
	Findings []NucleiFinding `json:"findings,omitempty"`
}

type NucleiFinding struct {
	Template         string         `json:"template,omitempty"`
	TemplateURL      string         `json:"template_url,omitempty"`
	TemplateID       string         `json:"template_id,omitempty"`
	TemplatePath     string         `json:"template_path,omitempty"`
	TemplateEncoded  string         `json:"template_encoded,omitempty"`
	Info             NucleiInfo     `json:"info,omitempty,omitzero"`
	MatcherName      string         `json:"matcher_name,omitempty"`
	ExtractorName    string         `json:"extractor_name,omitempty"`
	Type             string         `json:"type,omitempty"`
	Host             string         `json:"host,omitempty"`
	Port             string         `json:"port,omitempty"`
	Scheme           string         `json:"scheme,omitempty"`
	URL              string         `json:"url,omitempty"`
	Path             string         `json:"path,omitempty"`
	MatchedAt        string         `json:"matched_at,omitempty"`
	ExtractedResults []string       `json:"extracted_results,omitempty"`
	Request          string         `json:"request,omitempty"`
	Response         string         `json:"response,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	IP               string         `json:"ip,omitempty"`
	Timestamp        string         `json:"timestamp,omitempty"`
	Interaction      map[string]any `json:"interaction,omitempty"`
	CurlCommand      string         `json:"curl_command,omitempty"`
	MatcherStatus    bool           `json:"matcher_status,omitempty"`
	MatchedLines     []int          `json:"matched_lines,omitempty"`
	GlobalMatchers   bool           `json:"global_matchers,omitempty"`
	IssueTrackers    map[string]any `json:"issue_trackers,omitempty"`
	ReqURLPattern    string         `json:"req_url_pattern,omitempty"`
	IsFuzzingResult  bool           `json:"is_fuzzing_result,omitempty"`
	FuzzingMethod    string         `json:"fuzzing_method,omitempty"`
	FuzzingParameter string         `json:"fuzzing_parameter,omitempty"`
	FuzzingPosition  string         `json:"fuzzing_position,omitempty"`
	AnalyzerDetails  string         `json:"analyzer_details,omitempty"`
	Error            string         `json:"error,omitempty"`
}

type NucleiInfo struct {
	Name           string               `json:"name,omitempty"`
	Authors        []string             `json:"authors,omitempty"`
	Severity       string               `json:"severity,omitempty"`
	Description    string               `json:"description,omitempty"`
	Impact         string               `json:"impact,omitempty"`
	Remediation    string               `json:"remediation,omitempty"`
	References     []string             `json:"references,omitempty"`
	Tags           []string             `json:"tags,omitempty"`
	Classification NucleiClassification `json:"classification,omitempty,omitzero"`
	Metadata       map[string]any       `json:"metadata,omitempty"`
	Extra          map[string]any       `json:"extra,omitempty"`
}

type NucleiClassification struct {
	CVEIDs         []string `json:"cve_ids,omitempty"`
	CWEIDs         []string `json:"cwe_ids,omitempty"`
	CVSSMetrics    string   `json:"cvss_metrics,omitempty"`
	CVSSScore      float64  `json:"cvss_score,omitempty"`
	EPSSScore      float64  `json:"epss_score,omitempty"`
	EPSSPercentile float64  `json:"epss_percentile,omitempty"`
	CPE            string   `json:"cpe,omitempty"`
}

type NucleiJSONParser struct{}

func (p NucleiJSONParser) Name() string {
	return "nuclei-json"
}

func (p NucleiJSONParser) IsCompatible(content string) bool {
	findings, err := parseNucleiJSON(content)
	return err == nil && len(findings) > 0
}

func (p NucleiJSONParser) Parse(content string) (interface{}, error) {
	findings, err := parseNucleiJSON(content)
	if err != nil {
		return nil, err
	}

	return NucleiResult{Findings: findings}, nil
}

type NucleiStandardParser struct{}

func (p NucleiStandardParser) Name() string {
	return "nuclei-standard"
}

func (p NucleiStandardParser) IsCompatible(content string) bool {
	return len(parseNucleiStandard(content)) > 0
}

func (p NucleiStandardParser) Parse(content string) (interface{}, error) {
	return NucleiResult{Findings: parseNucleiStandard(content)}, nil
}

type rawNucleiFinding struct {
	Template         string         `json:"template"`
	TemplateURL      string         `json:"template-url"`
	TemplateID       string         `json:"template-id"`
	TemplatePath     string         `json:"template-path"`
	TemplateEncoded  string         `json:"template-encoded"`
	Info             rawNucleiInfo  `json:"info"`
	MatcherName      string         `json:"matcher-name"`
	ExtractorName    string         `json:"extractor-name"`
	Type             string         `json:"type"`
	Host             string         `json:"host"`
	Port             string         `json:"port"`
	Scheme           string         `json:"scheme"`
	URL              string         `json:"url"`
	Path             string         `json:"path"`
	MatchedAt        string         `json:"matched-at"`
	ExtractedResults []string       `json:"extracted-results"`
	Request          string         `json:"request"`
	Response         string         `json:"response"`
	Metadata         map[string]any `json:"meta"`
	IP               string         `json:"ip"`
	Timestamp        string         `json:"timestamp"`
	Interaction      map[string]any `json:"interaction"`
	CurlCommand      string         `json:"curl-command"`
	MatcherStatus    bool           `json:"matcher-status"`
	MatchedLines     []int          `json:"matched-line"`
	GlobalMatchers   bool           `json:"global-matchers"`
	IssueTrackers    map[string]any `json:"issue_trackers"`
	ReqURLPattern    string         `json:"req_url_pattern"`
	IsFuzzingResult  bool           `json:"is_fuzzing_result"`
	FuzzingMethod    string         `json:"fuzzing_method"`
	FuzzingParameter string         `json:"fuzzing_parameter"`
	FuzzingPosition  string         `json:"fuzzing_position"`
	AnalyzerDetails  string         `json:"analyzer_details"`
	Error            string         `json:"error"`
}

type rawNucleiInfo struct {
	Name           string                  `json:"name"`
	Author         flexibleStringSlice     `json:"author"`
	Authors        flexibleStringSlice     `json:"authors"`
	Severity       string                  `json:"severity"`
	Description    string                  `json:"description"`
	Impact         string                  `json:"impact"`
	Remediation    string                  `json:"remediation"`
	Reference      flexibleStringSlice     `json:"reference"`
	References     flexibleStringSlice     `json:"references"`
	Tags           flexibleStringSlice     `json:"tags"`
	Classification rawNucleiClassification `json:"classification"`
	Metadata       map[string]any          `json:"metadata"`
	Extra          map[string]any          `json:"-"`
}

type rawNucleiClassification struct {
	CVEIDs         flexibleStringSlice `json:"cve-id"`
	CWEIDs         flexibleStringSlice `json:"cwe-id"`
	CVSSMetrics    string              `json:"cvss-metrics"`
	CVSSScore      float64             `json:"cvss-score"`
	EPSSScore      float64             `json:"epss-score"`
	EPSSPercentile float64             `json:"epss-percentile"`
	CPE            string              `json:"cpe"`
}

type flexibleStringSlice []string

func (s *flexibleStringSlice) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	var values []string
	if err := json.Unmarshal(data, &values); err == nil {
		*s = compactNucleiStrings(values)
		return nil
	}

	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		if value == "" {
			return nil
		}
		*s = []string{value}
		return nil
	}

	var rawValues []any
	if err := json.Unmarshal(data, &rawValues); err == nil {
		values = make([]string, 0, len(rawValues))
		for _, rawValue := range rawValues {
			values = append(values, fmt.Sprint(rawValue))
		}
		*s = compactNucleiStrings(values)
		return nil
	}

	return fmt.Errorf("expected string or string array")
}

func (r *rawNucleiInfo) UnmarshalJSON(data []byte) error {
	type info rawNucleiInfo
	var decoded info
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, knownField := range []string{
		"name", "author", "authors", "severity", "description", "impact", "remediation",
		"reference", "references", "tags", "classification", "metadata",
	} {
		delete(fields, knownField)
	}

	decoded.Extra = make(map[string]any, len(fields))
	for key, value := range fields {
		var decodedValue any
		if err := json.Unmarshal(value, &decodedValue); err != nil {
			continue
		}
		decoded.Extra[key] = decodedValue
	}
	if len(decoded.Extra) == 0 {
		decoded.Extra = nil
	}

	*r = rawNucleiInfo(decoded)
	return nil
}

func parseNucleiJSON(content string) ([]NucleiFinding, error) {
	content = strings.TrimSpace(strings.TrimPrefix(content, "\ufeff"))
	if content == "" {
		return nil, errors.New("empty nuclei JSON output")
	}

	if strings.HasPrefix(content, "[") {
		return parseNucleiJSONArray(content)
	}

	if strings.HasPrefix(content, "{") {
		findings, err := parseSingleNucleiJSONObject(content)
		if err == nil {
			return findings, nil
		}
	}

	return parseNucleiJSONLines(content)
}

func parseNucleiJSONArray(content string) ([]NucleiFinding, error) {
	var rawFindings []rawNucleiFinding
	if err := json.Unmarshal([]byte(content), &rawFindings); err != nil {
		return nil, fmt.Errorf("parse nuclei JSON array: %w", err)
	}

	findings := make([]NucleiFinding, 0, len(rawFindings))
	for index, rawFinding := range rawFindings {
		if !rawFinding.isNucleiFinding() {
			return nil, fmt.Errorf("entry %d is not a nuclei finding", index+1)
		}
		findings = append(findings, rawFinding.toFinding())
	}
	return findings, nil
}

func parseSingleNucleiJSONObject(content string) ([]NucleiFinding, error) {
	var rawFinding rawNucleiFinding
	if err := json.Unmarshal([]byte(content), &rawFinding); err != nil {
		return nil, fmt.Errorf("parse nuclei JSON object: %w", err)
	}
	if !rawFinding.isNucleiFinding() {
		return nil, errors.New("JSON object is not a nuclei finding")
	}
	return []NucleiFinding{rawFinding.toFinding()}, nil
}

func parseNucleiJSONLines(content string) ([]NucleiFinding, error) {
	var findings []NucleiFinding
	for index, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var rawFinding rawNucleiFinding
		if err := json.Unmarshal([]byte(line), &rawFinding); err != nil {
			return nil, fmt.Errorf("parse nuclei JSON line %d: %w", index+1, err)
		}
		if !rawFinding.isNucleiFinding() {
			return nil, fmt.Errorf("line %d is not a nuclei finding", index+1)
		}
		findings = append(findings, rawFinding.toFinding())
	}

	if len(findings) == 0 {
		return nil, errors.New("no nuclei JSON findings found")
	}
	return findings, nil
}

func (r rawNucleiFinding) isNucleiFinding() bool {
	if r.TemplateID == "" {
		return false
	}
	return r.Type != "" || r.MatchedAt != "" || r.Host != "" || r.URL != "" || r.Info.hasData()
}

func (r rawNucleiFinding) toFinding() NucleiFinding {
	finding := NucleiFinding{
		Template:         r.Template,
		TemplateURL:      r.TemplateURL,
		TemplateID:       r.TemplateID,
		TemplatePath:     r.TemplatePath,
		TemplateEncoded:  r.TemplateEncoded,
		Info:             r.Info.toInfo(),
		MatcherName:      r.MatcherName,
		ExtractorName:    r.ExtractorName,
		Type:             r.Type,
		Host:             r.Host,
		Port:             r.Port,
		Scheme:           r.Scheme,
		URL:              r.URL,
		Path:             r.Path,
		MatchedAt:        r.MatchedAt,
		ExtractedResults: compactNucleiStrings(r.ExtractedResults),
		Request:          r.Request,
		Response:         r.Response,
		Metadata:         r.Metadata,
		IP:               r.IP,
		Timestamp:        r.Timestamp,
		Interaction:      r.Interaction,
		CurlCommand:      r.CurlCommand,
		MatcherStatus:    r.MatcherStatus,
		MatchedLines:     r.MatchedLines,
		GlobalMatchers:   r.GlobalMatchers,
		IssueTrackers:    r.IssueTrackers,
		ReqURLPattern:    r.ReqURLPattern,
		IsFuzzingResult:  r.IsFuzzingResult,
		FuzzingMethod:    r.FuzzingMethod,
		FuzzingParameter: r.FuzzingParameter,
		FuzzingPosition:  r.FuzzingPosition,
		AnalyzerDetails:  r.AnalyzerDetails,
		Error:            r.Error,
	}

	if finding.URL == "" {
		setNucleiTargetFields(&finding, finding.MatchedAt)
	}
	return finding
}

func (r rawNucleiInfo) hasData() bool {
	return r.Name != "" || r.Severity != "" || len(r.Author) > 0 || len(r.Authors) > 0 || len(r.Tags) > 0
}

func (r rawNucleiInfo) toInfo() NucleiInfo {
	authors := append([]string{}, r.Author...)
	authors = append(authors, r.Authors...)
	references := append([]string{}, r.Reference...)
	references = append(references, r.References...)

	return NucleiInfo{
		Name:           r.Name,
		Authors:        compactNucleiStrings(authors),
		Severity:       r.Severity,
		Description:    r.Description,
		Impact:         r.Impact,
		Remediation:    r.Remediation,
		References:     compactNucleiStrings(references),
		Tags:           splitCommaSeparated(r.Tags),
		Classification: r.Classification.toClassification(),
		Metadata:       r.Metadata,
		Extra:          r.Extra,
	}
}

func (r rawNucleiClassification) toClassification() NucleiClassification {
	return NucleiClassification{
		CVEIDs:         splitCommaSeparated(r.CVEIDs),
		CWEIDs:         splitCommaSeparated(r.CWEIDs),
		CVSSMetrics:    r.CVSSMetrics,
		CVSSScore:      r.CVSSScore,
		EPSSScore:      r.EPSSScore,
		EPSSPercentile: r.EPSSPercentile,
		CPE:            r.CPE,
	}
}

var nucleiANSIEscapeRegex = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func parseNucleiStandard(content string) []NucleiFinding {
	findings := []NucleiFinding{}
	for _, line := range strings.Split(content, "\n") {
		finding, ok := parseNucleiStandardLine(line)
		if ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func parseNucleiStandardLine(line string) (NucleiFinding, bool) {
	line = strings.TrimSpace(nucleiANSIEscapeRegex.ReplaceAllString(line, ""))
	if line == "" {
		return NucleiFinding{}, false
	}

	tokens, rest := leadingBracketTokens(line)
	if len(tokens) < 3 || rest == "" {
		return NucleiFinding{}, false
	}

	start := 0
	if len(tokens) >= 4 && looksLikeNucleiTimestamp(tokens[0]) {
		start = 1
	}
	if len(tokens)-start < 3 {
		return NucleiFinding{}, false
	}

	templateID := strings.TrimSpace(tokens[start])
	resultType := strings.TrimSpace(tokens[start+1])
	severity := strings.ToLower(strings.TrimSpace(tokens[start+2]))
	if templateID == "" || resultType == "" || !isNucleiSeverity(severity) {
		return NucleiFinding{}, false
	}

	matchedAt, trailing, ok := strings.Cut(strings.TrimSpace(rest), " ")
	if !ok {
		matchedAt = strings.TrimSpace(rest)
		trailing = ""
	}
	if matchedAt == "" {
		return NucleiFinding{}, false
	}

	finding := NucleiFinding{
		TemplateID: templateID,
		Type:       resultType,
		Info: NucleiInfo{
			Severity: severity,
		},
		MatchedAt: matchedAt,
	}
	setNucleiTargetFields(&finding, matchedAt)
	finding.ExtractedResults = parseNucleiStandardExtra(trailing)
	return finding, true
}

func leadingBracketTokens(line string) ([]string, string) {
	tokens := []string{}
	remaining := strings.TrimSpace(line)
	for strings.HasPrefix(remaining, "[") {
		end := strings.Index(remaining, "]")
		if end <= 0 {
			break
		}
		tokens = append(tokens, remaining[1:end])
		remaining = strings.TrimSpace(remaining[end+1:])
	}
	return tokens, remaining
}

func looksLikeNucleiTimestamp(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) >= len("2006-01-02") && value[4] == '-' && value[7] == '-'
}

func isNucleiSeverity(value string) bool {
	switch value {
	case "info", "low", "medium", "high", "critical", "unknown":
		return true
	default:
		return false
	}
}

func parseNucleiStandardExtra(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	tokens, rest := leadingBracketTokens(value)
	if len(tokens) > 0 && rest == "" {
		return compactNucleiStrings(tokens)
	}
	return []string{value}
}

func setNucleiTargetFields(finding *NucleiFinding, target string) {
	if target == "" {
		return
	}

	parsed, err := url.Parse(target)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		finding.URL = target
		finding.Scheme = parsed.Scheme
		finding.Host = parsed.Hostname()
		finding.Port = parsed.Port()
		finding.Path = parsed.EscapedPath()
		return
	}

	finding.Host = target
}

func splitCommaSeparated(values []string) []string {
	splitValues := []string{}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				splitValues = append(splitValues, part)
			}
		}
	}
	return compactNucleiStrings(splitValues)
}

func compactNucleiStrings(values []string) []string {
	compacted := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			compacted = append(compacted, value)
		}
	}
	if len(compacted) == 0 {
		return nil
	}
	return compacted
}
