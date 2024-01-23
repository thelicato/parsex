package types

type Parser interface {
	Name() string
	IsCompatible(content string) bool
	Parse(content string) (interface{}, error)
}
