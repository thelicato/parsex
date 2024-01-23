package utils

import (
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
)

// Global variables
var (
	ServiceMapper map[string]string
	CVERegex      = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
	CWERegex      = regexp.MustCompile(`CWE-\d{1,4}`)
	CVSSRange     = []struct {
		Lower    float64
		Upper    float64
		Severity string
	}{
		{0.0, 0.1, "info"},
		{0.1, 4.0, "low"},
		{4.0, 7.0, "med"},
		{7.0, 9.0, "high"},
		{9.0, 10.1, "critical"},
	}
)

// GetVulnWebURLFields extracts and returns fields from a given URL
func GetVulnWebURLFields(urlStr string) (map[string]string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"website": parsedURL.Scheme + "://" + parsedURL.Host,
		"path":    parsedURL.Path,
		"query":   parsedURL.RawQuery,
	}, nil
}

// GetSeverityFromCVSS returns the severity level based on CVSS score
func GetSeverityFromCVSS(cvssStr string) string {
	cvss, err := strconv.ParseFloat(cvssStr, 64)
	if err != nil {
		return "unclassified"
	}

	for _, rangeVal := range CVSSRange {
		if rangeVal.Lower <= cvss && cvss < rangeVal.Upper {
			return rangeVal.Severity
		}
	}
	return "unclassified"
}

// ItsCVE checks if the list contains CVEs and returns them
func ItsCVE(cves []string) []string {
	var result []string
	for _, cve := range cves {
		if CVERegex.MatchString(cve) {
			result = append(result, cve)
		}
	}
	return result
}

// ItsCWE checks if the list contains CWEs and returns them
func ItsCWE(cwes []string) []string {
	var result []string
	for _, cwe := range cwes {
		if CWERegex.MatchString(cwe) {
			result = append(result, cwe)
		}
	}
	return result
}

func CheckPathExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func ReadInput(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func ParseInt(s string) int {
	val, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return val
}

func ParseFloat(s string) float64 {
	val, err := strconv.ParseFloat(s, 64)
	if err != nil {
		panic(err)
	}
	return val
}
