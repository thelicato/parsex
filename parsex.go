package main

import (
	"github.com/thelicato/parsex/cmd"
	"github.com/thelicato/parsex/pkg/utils"
)

var version = "0.1.0"

func main() {
	utils.Banner(version)
	cmd.Execute()
}
