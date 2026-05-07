package main

import (
	"fmt"
	"os"

	"github.com/thelicato/parsex/internal/cli"
)

var version = "0.1.0"

func main() {
	if err := cli.Execute(version); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
