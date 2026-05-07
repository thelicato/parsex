package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootCommandParsesInput(t *testing.T) {
	cmd := NewRootCommand("test")
	output := bytes.Buffer{}
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"-i", "../../samples/nmap7"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute command: %v", err)
	}

	if !strings.Contains(output.String(), "\n  \"parser\": \"nmap standard\"") {
		t.Fatalf("expected pretty JSON parser output, got %q", output.String())
	}

	var result struct {
		Parser            string   `json:"parser"`
		CompatibleParsers []string `json:"compatible_parsers"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if result.Parser != "nmap standard" {
		t.Fatalf("expected nmap standard parser, got %q", result.Parser)
	}
	if len(result.CompatibleParsers) != 1 || result.CompatibleParsers[0] != "nmap standard" {
		t.Fatalf("expected compatible parser list, got %#v", result.CompatibleParsers)
	}
}

func TestRootCommandNoCompatibleParser(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "unsupported.txt")
	if err := os.WriteFile(inputPath, []byte("unsupported"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	cmd := NewRootCommand("test")
	output := bytes.Buffer{}
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"-i", inputPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute command: %v", err)
	}

	if !strings.Contains(output.String(), "No compatible parser found") {
		t.Fatalf("expected no parser output, got %q", output.String())
	}
}
