package parsex

import (
	"errors"
	"fmt"

	parserpkg "github.com/thelicato/parsex/pkg/parsers"
	"github.com/thelicato/parsex/pkg/utils"
)

// ErrNoCompatibleParser is returned when no registered parser recognizes the input.
var ErrNoCompatibleParser = errors.New("no compatible parser found")

// Parser is implemented by every supported security tool output parser.
type Parser = parserpkg.Parser

// Result contains the parser name and the parser-specific data it extracted.
type Result struct {
	Parser string `json:"parser"`
	Data   any    `json:"data"`
}

type config struct {
	parsers []Parser
}

// Option customizes parsing behavior.
type Option interface {
	apply(*config)
}

type optionFunc func(*config)

func (f optionFunc) apply(cfg *config) {
	f(cfg)
}

// WithParsers overrides the default parser list.
func WithParsers(parsers ...Parser) Option {
	return optionFunc(func(cfg *config) {
		cfg.parsers = append([]Parser(nil), parsers...)
	})
}

// DefaultParsers returns the built-in parser list.
func DefaultParsers() []Parser {
	return parserpkg.DefaultParsers()
}

// Parse detects a compatible parser and parses the provided content.
func Parse(content string, opts ...Option) (Result, error) {
	cfg := config{
		parsers: DefaultParsers(),
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt.apply(&cfg)
	}

	for _, parser := range cfg.parsers {
		if !parser.IsCompatible(content) {
			continue
		}

		data, err := parser.Parse(content)
		if err != nil {
			return Result{}, fmt.Errorf("%s parser failed: %w", parser.Name(), err)
		}

		return Result{
			Parser: parser.Name(),
			Data:   data,
		}, nil
	}

	return Result{}, ErrNoCompatibleParser
}

// ParseFile reads a file and parses its content.
func ParseFile(filePath string, opts ...Option) (Result, error) {
	content, err := utils.ReadInput(filePath)
	if err != nil {
		return Result{}, fmt.Errorf("read input: %w", err)
	}

	return Parse(content, opts...)
}
