package parsers

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type FFUFResult struct {
	CommandLine string         `json:"commandline,omitempty"`
	Time        string         `json:"time,omitempty"`
	Results     []FFUFFinding  `json:"results,omitempty"`
	Config      map[string]any `json:"config,omitempty"`
}

type FFUFFinding struct {
	Input               map[string]string   `json:"input,omitempty"`
	InputValue          string              `json:"input_value,omitempty"`
	Position            int                 `json:"position,omitempty"`
	Status              int                 `json:"status,omitempty"`
	Length              int                 `json:"length,omitempty"`
	Words               int                 `json:"words,omitempty"`
	Lines               int                 `json:"lines,omitempty"`
	ContentType         string              `json:"content_type,omitempty"`
	RedirectLocation    string              `json:"redirect_location,omitempty"`
	Scraper             map[string][]string `json:"scraper,omitempty"`
	Duration            string              `json:"duration,omitempty"`
	DurationNanoseconds int64               `json:"duration_nanoseconds,omitempty"`
	ResultFile          string              `json:"result_file,omitempty"`
	URL                 string              `json:"url,omitempty"`
	Host                string              `json:"host,omitempty"`
	FFUFHash            string              `json:"ffuf_hash,omitempty"`
	Extra               map[string]string   `json:"extra,omitempty"`
}

type FFUFJSONParser struct{}

func (p FFUFJSONParser) Name() string {
	return "ffuf-json"
}

func (p FFUFJSONParser) IsCompatible(content string) bool {
	_, err := parseFFUFJSON(content)
	return err == nil
}

func (p FFUFJSONParser) Parse(content string) (interface{}, error) {
	return parseFFUFJSON(content)
}

type FFUFStandardParser struct{}

func (p FFUFStandardParser) Name() string {
	return "ffuf-standard"
}

func (p FFUFStandardParser) IsCompatible(content string) bool {
	return len(parseFFUFStandard(content)) > 0
}

func (p FFUFStandardParser) Parse(content string) (interface{}, error) {
	return FFUFResult{Results: parseFFUFStandard(content)}, nil
}

type rawFFUFOutput struct {
	CommandLine string           `json:"commandline"`
	Time        string           `json:"time"`
	Results     []rawFFUFFinding `json:"results"`
	Config      map[string]any   `json:"config"`
}

type rawFFUFFinding struct {
	Input               map[string]any  `json:"input"`
	Position            flexibleFFUFInt `json:"position"`
	Status              flexibleFFUFInt `json:"status"`
	StatusCode          flexibleFFUFInt `json:"status_code"`
	Length              flexibleFFUFInt `json:"length"`
	ContentLength       flexibleFFUFInt `json:"content_length"`
	Words               flexibleFFUFInt `json:"words"`
	ContentWords        flexibleFFUFInt `json:"content_words"`
	Lines               flexibleFFUFInt `json:"lines"`
	ContentLines        flexibleFFUFInt `json:"content_lines"`
	ContentType         string          `json:"content-type"`
	ContentTypeAlt      string          `json:"content_type"`
	RedirectLocation    string          `json:"redirectlocation"`
	RedirectLocationAlt string          `json:"redirect_location"`
	Scraper             map[string]any  `json:"scraper"`
	Duration            flexibleFFUFInt `json:"duration"`
	DurationAlt         string          `json:"duration_str"`
	ResultFile          string          `json:"resultfile"`
	ResultFileAlt       string          `json:"result_file"`
	URL                 string          `json:"url"`
	Host                string          `json:"host"`
	FFUFHash            string          `json:"Ffufhash"`
	FFUFHashAlt         string          `json:"ffuf_hash"`
}

type flexibleFFUFInt struct {
	value int64
	set   bool
}

func (i *flexibleFFUFInt) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	var integer int64
	if err := json.Unmarshal(data, &integer); err == nil {
		i.value = integer
		i.set = true
		return nil
	}

	var floating float64
	if err := json.Unmarshal(data, &floating); err == nil {
		if math.IsNaN(floating) || math.IsInf(floating, 0) {
			return fmt.Errorf("invalid number %q", string(data))
		}
		i.value = int64(floating)
		i.set = true
		return nil
	}

	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fmt.Errorf("parse integer %q: %w", text, err)
	}
	i.value = parsed
	i.set = true
	return nil
}

func (i flexibleFFUFInt) int() int {
	return int(i.value)
}

func (i flexibleFFUFInt) int64() int64 {
	return i.value
}

func parseFFUFJSON(content string) (FFUFResult, error) {
	content = strings.TrimSpace(strings.TrimPrefix(content, "\ufeff"))
	if content == "" {
		return FFUFResult{}, errors.New("empty ffuf JSON output")
	}

	if strings.HasPrefix(content, "[") {
		return parseFFUFJSONArray(content)
	}

	if strings.HasPrefix(content, "{") {
		result, err := parseFFUFJSONObject(content)
		if err == nil {
			return result, nil
		}
	}

	return parseFFUFJSONLines(content)
}

func parseFFUFJSONObject(content string) (FFUFResult, error) {
	var output rawFFUFOutput
	if err := json.Unmarshal([]byte(content), &output); err != nil {
		return FFUFResult{}, fmt.Errorf("parse ffuf JSON object: %w", err)
	}

	if output.isFFUFOutput() {
		return output.toResult(), nil
	}

	var rawFinding rawFFUFFinding
	if err := json.Unmarshal([]byte(content), &rawFinding); err != nil {
		return FFUFResult{}, fmt.Errorf("parse ffuf JSON result: %w", err)
	}
	if !rawFinding.isFFUFFinding() {
		return FFUFResult{}, errors.New("JSON object is not a ffuf result")
	}
	return FFUFResult{Results: []FFUFFinding{rawFinding.toFinding()}}, nil
}

func parseFFUFJSONArray(content string) (FFUFResult, error) {
	var rawFindings []rawFFUFFinding
	if err := json.Unmarshal([]byte(content), &rawFindings); err != nil {
		return FFUFResult{}, fmt.Errorf("parse ffuf JSON array: %w", err)
	}

	findings := make([]FFUFFinding, 0, len(rawFindings))
	for index, rawFinding := range rawFindings {
		if !rawFinding.isFFUFFinding() {
			return FFUFResult{}, fmt.Errorf("entry %d is not a ffuf result", index+1)
		}
		findings = append(findings, rawFinding.toFinding())
	}
	if len(findings) == 0 {
		return FFUFResult{}, errors.New("no ffuf JSON results found")
	}
	return FFUFResult{Results: findings}, nil
}

func parseFFUFJSONLines(content string) (FFUFResult, error) {
	findings := []FFUFFinding{}
	for index, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var rawFinding rawFFUFFinding
		if err := json.Unmarshal([]byte(line), &rawFinding); err != nil {
			return FFUFResult{}, fmt.Errorf("parse ffuf JSON line %d: %w", index+1, err)
		}
		if !rawFinding.isFFUFFinding() {
			return FFUFResult{}, fmt.Errorf("line %d is not a ffuf result", index+1)
		}
		findings = append(findings, rawFinding.toFinding())
	}

	if len(findings) == 0 {
		return FFUFResult{}, errors.New("no ffuf JSON results found")
	}
	return FFUFResult{Results: findings}, nil
}

func (o rawFFUFOutput) isFFUFOutput() bool {
	return strings.Contains(strings.ToLower(o.CommandLine), "ffuf") || o.Results != nil
}

func (o rawFFUFOutput) toResult() FFUFResult {
	findings := make([]FFUFFinding, 0, len(o.Results))
	for _, rawFinding := range o.Results {
		findings = append(findings, rawFinding.toFinding())
	}
	return FFUFResult{
		CommandLine: o.CommandLine,
		Time:        o.Time,
		Results:     findings,
		Config:      o.Config,
	}
}

func (r rawFFUFFinding) isFFUFFinding() bool {
	return (r.Status.set || r.StatusCode.set) && (r.URL != "" || r.Host != "" || len(r.Input) > 0)
}

func (r rawFFUFFinding) toFinding() FFUFFinding {
	finding := FFUFFinding{
		Input:               normalizeFFUFInput(r.Input),
		Position:            r.Position.int(),
		Status:              firstFFUFInt(r.Status, r.StatusCode),
		Length:              firstFFUFInt(r.Length, r.ContentLength),
		Words:               firstFFUFInt(r.Words, r.ContentWords),
		Lines:               firstFFUFInt(r.Lines, r.ContentLines),
		ContentType:         firstFFUFString(r.ContentType, r.ContentTypeAlt),
		RedirectLocation:    firstFFUFString(r.RedirectLocation, r.RedirectLocationAlt),
		Scraper:             normalizeFFUFScraper(r.Scraper),
		DurationNanoseconds: r.Duration.int64(),
		ResultFile:          firstFFUFString(r.ResultFile, r.ResultFileAlt),
		URL:                 r.URL,
		Host:                r.Host,
		FFUFHash:            firstFFUFString(r.FFUFHash, r.FFUFHashAlt),
	}
	finding.Duration = r.DurationAlt
	if finding.Duration == "" && r.Duration.set {
		finding.Duration = time.Duration(r.Duration.int64()).String()
	}
	if finding.Host == "" {
		setFFUFTargetFields(&finding, finding.URL)
	}
	return finding
}

func firstFFUFInt(values ...flexibleFFUFInt) int {
	for _, value := range values {
		if value.set {
			return value.int()
		}
	}
	return 0
}

func firstFFUFString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func normalizeFFUFInput(input map[string]any) map[string]string {
	if len(input) == 0 {
		return nil
	}

	normalized := make(map[string]string, len(input))
	for key, value := range input {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		normalized[key] = normalizeFFUFValue(value)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizeFFUFScraper(scraper map[string]any) map[string][]string {
	if len(scraper) == 0 {
		return nil
	}

	normalized := make(map[string][]string, len(scraper))
	for key, value := range scraper {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		switch typedValue := value.(type) {
		case []any:
			values := make([]string, 0, len(typedValue))
			for _, item := range typedValue {
				values = append(values, normalizeFFUFValue(item))
			}
			normalized[key] = compactFFUFStrings(values)
		case []string:
			normalized[key] = compactFFUFStrings(typedValue)
		default:
			normalized[key] = compactFFUFStrings([]string{normalizeFFUFValue(typedValue)})
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizeFFUFValue(value any) string {
	switch typedValue := value.(type) {
	case string:
		return typedValue
	case []any:
		bytes := make([]byte, 0, len(typedValue))
		for _, item := range typedValue {
			floatValue, ok := item.(float64)
			if !ok || floatValue < 0 || floatValue > 255 || math.Trunc(floatValue) != floatValue {
				return fmt.Sprint(value)
			}
			bytes = append(bytes, byte(floatValue))
		}
		return string(bytes)
	case nil:
		return ""
	default:
		return fmt.Sprint(typedValue)
	}
}

var ffufANSIEscapeRegex = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
var ffufResultLineRegex = regexp.MustCompile(`^(.+?)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)(?:,\s*Duration:\s*([^\]]+))?\]`)
var ffufStatusOnlyLineRegex = regexp.MustCompile(`^\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)(?:,\s*Duration:\s*([^\]]+))?\]`)
var ffufDetailLineRegex = regexp.MustCompile(`^\*\s*([^|]+?)\s*\|\s*(.+)$`)

func parseFFUFStandard(content string) []FFUFFinding {
	lines := strings.Split(content, "\n")
	findings := []FFUFFinding{}
	for index := 0; index < len(lines); index++ {
		line := cleanFFUFLine(lines[index])
		if line == "" {
			continue
		}

		finding, ok := parseFFUFResultLine(line)
		if ok {
			findings = append(findings, finding)
			continue
		}

		finding, ok = parseFFUFStatusOnlyLine(line)
		if !ok {
			continue
		}

		for nextIndex := index + 1; nextIndex < len(lines); nextIndex++ {
			detailLine := cleanFFUFLine(lines[nextIndex])
			if detailLine == "" {
				index = nextIndex
				continue
			}
			if parseFFUFDetailLine(&finding, detailLine) {
				index = nextIndex
				continue
			}
			break
		}
		findings = append(findings, finding)
	}
	return findings
}

func parseFFUFResultLine(line string) (FFUFFinding, bool) {
	matches := ffufResultLineRegex.FindStringSubmatch(line)
	if matches == nil {
		return FFUFFinding{}, false
	}

	inputValue := strings.TrimSpace(matches[1])
	finding := ffufFindingFromMetrics(matches[2], matches[3], matches[4], matches[5], matches[6])
	finding.InputValue = inputValue
	if inputValue != "" {
		finding.Input = map[string]string{"FUZZ": inputValue}
	}
	return finding, true
}

func parseFFUFStatusOnlyLine(line string) (FFUFFinding, bool) {
	matches := ffufStatusOnlyLineRegex.FindStringSubmatch(line)
	if matches == nil {
		return FFUFFinding{}, false
	}
	return ffufFindingFromMetrics(matches[1], matches[2], matches[3], matches[4], matches[5]), true
}

func ffufFindingFromMetrics(status string, length string, words string, lines string, duration string) FFUFFinding {
	finding := FFUFFinding{
		Status:   atoiFFUF(status),
		Length:   atoiFFUF(length),
		Words:    atoiFFUF(words),
		Lines:    atoiFFUF(lines),
		Duration: strings.TrimSpace(duration),
	}
	if finding.Duration != "" {
		if parsedDuration, err := time.ParseDuration(finding.Duration); err == nil {
			finding.DurationNanoseconds = int64(parsedDuration)
		}
	}
	return finding
}

func parseFFUFDetailLine(finding *FFUFFinding, line string) bool {
	matches := ffufDetailLineRegex.FindStringSubmatch(line)
	if matches == nil {
		return false
	}

	key := strings.TrimSpace(matches[1])
	value := strings.TrimSpace(matches[2])
	if key == "" || value == "" {
		return true
	}

	switch strings.ToUpper(key) {
	case "URL":
		finding.URL = value
		setFFUFTargetFields(finding, value)
	case "RES", "RESULTFILE", "RESULT_FILE":
		finding.ResultFile = value
	default:
		if finding.Input == nil {
			finding.Input = map[string]string{}
		}
		finding.Input[key] = value
		if finding.Extra == nil {
			finding.Extra = map[string]string{}
		}
		finding.Extra[key] = value
	}
	return true
}

func cleanFFUFLine(line string) string {
	return strings.TrimSpace(ffufANSIEscapeRegex.ReplaceAllString(line, ""))
}

func atoiFFUF(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return parsed
}

func setFFUFTargetFields(finding *FFUFFinding, target string) {
	if target == "" {
		return
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" {
		return
	}
	finding.Host = parsed.Hostname()
}

func compactFFUFStrings(values []string) []string {
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
