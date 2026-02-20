package main

import (
	"github.com/thelicato/parsecx/cmd"
	"github.com/thelicato/parsecx/pkg/utils"
)

var version = "0.1.0"

func main() {
	utils.Banner(version)
	cmd.Execute()
}
