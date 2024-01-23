package main

import (
	"github.com/groundsec/parsecx/cmd"
	"github.com/groundsec/parsecx/pkg/utils"
)

var version = "0.1.0"

func main() {
	utils.Banner(version)
	cmd.Execute()
}
