package parsers

// Parser detects and parses one security tool output format.
type Parser interface {
	Name() string
	IsCompatible(content string) bool
	Parse(content string) (interface{}, error)
}

// DefaultParsers returns the built-in parser list.
func DefaultParsers() []Parser {
	return []Parser{
		NmapXMLParser{},
		NmapGrepableParser{},
		StandardNmapParser{},
		NucleiJSONParser{},
		NucleiStandardParser{},
		FFUFJSONParser{},
		FFUFStandardParser{},
		GobusterStandardParser{},
		SubfinderJSONParser{},
		SubfinderStandardParser{},
	}
}
