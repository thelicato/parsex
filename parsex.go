package parsex

import (
	"errors"
	"fmt"
	"strings"

	parserpkg "github.com/thelicato/parsex/pkg/parsers"
	"github.com/thelicato/parsex/pkg/utils"
)

// ErrNoCompatibleParser is returned when no registered parser recognizes the input.
var ErrNoCompatibleParser = errors.New("no compatible parser found")

// ErrParserNotFound is returned when a requested parser is not registered.
var ErrParserNotFound = errors.New("parser not found")

// ErrParserNotCompatible is returned when a requested parser does not recognize the input.
var ErrParserNotCompatible = errors.New("parser is not compatible with input")

// Parser is implemented by every supported security tool output parser.
type Parser = parserpkg.Parser

// Result contains the selected parser, every compatible parser, and the parsed data.
type Result struct {
	Parser            string   `json:"parser"`
	CompatibleParsers []string `json:"compatible_parsers,omitempty"`
	Data              any      `json:"data"`
}

type config struct {
	parsers    []Parser
	parserName string
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

// WithParserName selects one registered parser by name.
func WithParserName(name string) Option {
	return optionFunc(func(cfg *config) {
		cfg.parserName = strings.TrimSpace(name)
	})
}

// DefaultParsers returns the built-in parser list.
func DefaultParsers() []Parser {
	return parserpkg.DefaultParsers()
}

// CompatibleParsers returns the names of every parser that recognizes the content.
func CompatibleParsers(content string, opts ...Option) []string {
	cfg := newConfig(opts...)
	return parserNames(findCompatibleParsers(content, cfg.parsers))
}

// Parse detects compatible parsers and parses the content with the selected parser.
func Parse(content string, opts ...Option) (Result, error) {
	cfg := newConfig(opts...)

	if cfg.parserName != "" && findParserByName(cfg.parserName, cfg.parsers) == nil {
		return Result{}, fmt.Errorf(
			"%w: %s; available parsers: %s",
			ErrParserNotFound,
			cfg.parserName,
			strings.Join(parserNames(cfg.parsers), ", "),
		)
	}

	compatibleParsers := findCompatibleParsers(content, cfg.parsers)
	if len(compatibleParsers) == 0 {
		return Result{}, ErrNoCompatibleParser
	}

	parser := compatibleParsers[0]
	if cfg.parserName != "" {
		parser = findParserByName(cfg.parserName, compatibleParsers)
		if parser == nil {
			return Result{}, fmt.Errorf(
				"%w: %s; compatible parsers: %s",
				ErrParserNotCompatible,
				cfg.parserName,
				strings.Join(parserNames(compatibleParsers), ", "),
			)
		}
	}

	data, err := parser.Parse(content)
	if err != nil {
		return Result{}, fmt.Errorf("%s parser failed: %w", parser.Name(), err)
	}

	return Result{
		Parser:            parser.Name(),
		CompatibleParsers: parserNames(compatibleParsers),
		Data:              data,
	}, nil
}

// ParseFile reads a file and parses its content.
func ParseFile(filePath string, opts ...Option) (Result, error) {
	content, err := utils.ReadInput(filePath)
	if err != nil {
		return Result{}, fmt.Errorf("read input: %w", err)
	}

	return Parse(content, opts...)
}

func newConfig(opts ...Option) config {
	cfg := config{parsers: DefaultParsers()}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt.apply(&cfg)
	}
	return cfg
}

func findCompatibleParsers(content string, parsers []Parser) []Parser {
	compatibleParsers := make([]Parser, 0, len(parsers))
	for _, parser := range parsers {
		if parser.IsCompatible(content) {
			compatibleParsers = append(compatibleParsers, parser)
		}
	}
	return compatibleParsers
}

func findParserByName(name string, parsers []Parser) Parser {
	normalizedName := normalizeParserName(name)
	for _, parser := range parsers {
		if normalizeParserName(parser.Name()) == normalizedName {
			return parser
		}
	}
	return nil
}

func parserNames(parsers []Parser) []string {
	names := make([]string, 0, len(parsers))
	for _, parser := range parsers {
		names = append(names, parser.Name())
	}
	return names
}

func normalizeParserName(name string) string {
	name = strings.NewReplacer("-", " ", "_", " ").Replace(name)
	return strings.Join(strings.Fields(strings.ToLower(name)), " ")
}
