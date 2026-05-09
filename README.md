<h1 align="center">
	<img src="./logo.svg?raw=true" width="200">
</h1>

<h4 align="center">Parse and extract key data across multiple security tools</h4>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-license">License</a> •
</p>

---

`parsex` is a powerful command-line tool designed to streamline the process of parsing and extracting data from various security tools' outputs. It simplifies the complex task of data analysis in cybersecurity by providing a unified solution for interpreting and organizing data from multiple sources.

With `parsex`, you can efficiently process and extract essential information from different security tool outputs, enabling faster and more informed decision-making in your cybersecurity operations.

The goal is to obtain a tool that meets the requirements of the community, therefore suggestions and PRs are very welcome!

## ⚡ Features

- Unified parsing
- Streamlined workflow
- CLI and library modes
- Sample Files

This is the current list of compatible tools:

- nmap (`nmap-standard`, `nmap-xml`, `nmap-grepable`)
- nuclei (`nuclei-standard`, `nuclei-json` for JSON and JSONL output)
- ffuf (`ffuf-standard`, `ffuf-json` for JSON and JSONL output)

## 📚 Usage

### CLI mode

```
parsex -h
```

This will display the help for the tool

```
Parse and extract key data across multiple security tools

Usage:
  parsex [flags]

Flags:
  -h, --help            help for parsex
  -i, --input string    Input to parse
  -p, --parser string   Parser to use
  -v, --version         version for parsex
```

Parse a tool output file:

```
parsex -i samples/nmap7
```

Select a specific parser when more than one parser is compatible:

```
parsex -i samples/nmap7 --parser nmap-standard
```

CLI mode prints indented JSON. `parser` is the parser selected for the result, while `compatible_parsers` lists every parser that matched the input. If more than one parser matches, parsex uses the first parser in the configured parser order unless `--parser` selects one of the compatible parsers. Parser names are matched case-insensitively, and spaces, dashes, and underscores are equivalent. Parser names are emitted as lowercase dash-separated identifiers. If the selected parser is not compatible with the input, parsex returns an error.

### Library mode

```go
package main

import (
	"errors"
	"fmt"

	"github.com/thelicato/parsex"
)

func main() {
	result, err := parsex.ParseFile("samples/nmap7", parsex.WithParserName("nmap-standard"))
	if errors.Is(err, parsex.ErrNoCompatibleParser) {
		fmt.Println("unsupported input")
		return
	}
	if err != nil {
		panic(err)
	}

	fmt.Printf("parser=%s data=%#v\n", result.Parser, result.Data)
}
```

## 🚀 Installation

Run the following command to install the latest version:

```
go install github.com/thelicato/parsex/cmd/parsex@latest
```

Or you can simply grab an executable from the [Releases](./releases) page.

## 🪪 License

_parsex_ is made with 🖤 and released under the [GPL3 LICENSE](./LICENSE).
