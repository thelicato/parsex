package parsers

type Parser interface {
	Name() string
	IsCompatible(content string) bool
	Parse(content string) (interface{}, error)
}

func DefaultParsers() []Parser {
	return []Parser{
		NmapXMLParser{},
		NmapGrepableParser{},
		StandardNmapParser{},
	}
}
