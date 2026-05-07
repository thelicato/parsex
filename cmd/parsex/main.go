package main

import (
	"fmt"
	"os"

	"github.com/thelicato/parsex/internal/cli"
	"github.com/thelicato/parsex/pkg/utils"
)

var version = "0.1.0"

func main() {
	utils.Banner(version)

	if err := cli.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
