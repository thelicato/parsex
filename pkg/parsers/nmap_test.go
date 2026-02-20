package parsers_test

import (
	"fmt"
	"testing"

	"github.com/thelicato/parsecx/pkg/parsers"
	"github.com/thelicato/parsecx/pkg/types"
	"github.com/thelicato/parsecx/pkg/utils"
)

func TestXMLParser(t *testing.T) {

	xmlFiles := []string{"../../samples/nmap1.xml", "../../samples/nmap15.xml"}
	parser := types.Parser(parsers.NmapXMLParser{})

	for _, xmlFile := range xmlFiles {
		content, err := utils.ReadInput(xmlFile)
		if err != nil {
			panic(err)
		}

		if !parser.IsCompatible(content) {
			panic("Incompatible file")
		}

		parsedResult, err := parser.Parse(content)
		fmt.Println(parsedResult)
		if err != nil {
			panic(err)
		}

	}
}

func TestStandardParser(t *testing.T) {
	xmlFiles := []string{
		"../../samples/nmap2",
		"../../samples/nmap3",
		"../../samples/nmap4",
		"../../samples/nmap5",
		"../../samples/nmap6",
		"../../samples/nmap7",
		"../../samples/nmap8",
		"../../samples/nmap9",
		"../../samples/nmap10",
		"../../samples/nmap11",
		"../../samples/nmap12",
		"../../samples/nmap13",
		"../../samples/nmap14",
		"../../samples/nmap16",
		"../../samples/nmap17",
		"../../samples/nmap18",
		"../../samples/nmap19"}
	parser := types.Parser(parsers.StandardNmapParser{})

	for _, xmlFile := range xmlFiles {
		content, err := utils.ReadInput(xmlFile)
		if err != nil {
			panic(err)
		}

		if !parser.IsCompatible(content) {
			panic("Incompatible file")
		}

		parsedResult, err := parser.Parse(content)
		fmt.Println(parsedResult)
		if err != nil {
			panic(err)
		}

	}
}
