package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootCommandParsesInput(t *testing.T) {
	cmd := NewRootCommand()
	output := bytes.Buffer{}
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"-i", "../../samples/nmap7"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute command: %v", err)
	}

	if !strings.Contains(output.String(), "Parser nmap standard is compatible!") {
		t.Fatalf("expected parser output, got %q", output.String())
	}
}

func TestRootCommandNoCompatibleParser(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "unsupported.txt")
	if err := os.WriteFile(inputPath, []byte("unsupported"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	cmd := NewRootCommand()
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
