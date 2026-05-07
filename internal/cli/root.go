package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/thelicato/parsex"
)

type options struct {
	input  string
	parser string
}

func Execute(version string) error {
	return NewRootCommand(version).Execute()
}

func NewRootCommand(version string) *cobra.Command {
	opts := options{}

	rootCmd := &cobra.Command{
		Use:           "parsex",
		Short:         "Parse and extract key data across multiple security tools",
		Version:       version,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.input == "" {
				if err := cmd.Help(); err != nil {
					return err
				}
				return errors.New("input is required")
			}

			return processFile(cmd.OutOrStdout(), opts.input, opts.parser)
		},
	}
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	rootCmd.PersistentFlags().StringVarP(&opts.input, "input", "i", "", "Input to parse")
	rootCmd.PersistentFlags().StringVarP(&opts.parser, "parser", "p", "", "Parser to use")

	return rootCmd
}

func processFile(out io.Writer, filePath string, parserName string) error {
	result, err := parsex.ParseFile(filePath, parsex.WithParserName(parserName))
	if errors.Is(err, parsex.ErrNoCompatibleParser) {
		_, err = fmt.Fprintln(out, "No compatible parser found for the file.")
		return err
	}
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
