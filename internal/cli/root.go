package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/thelicato/parsex/pkg/parsers"
	"github.com/thelicato/parsex/pkg/utils"
)

type options struct {
	input string
}

func Execute() error {
	return NewRootCommand().Execute()
}

func NewRootCommand() *cobra.Command {
	opts := options{}

	rootCmd := &cobra.Command{
		Use:           "parsex",
		Short:         "Parse and extract key data across multiple security tools",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.input == "" {
				if err := cmd.Help(); err != nil {
					return err
				}
				return errors.New("input is required")
			}

			if !utils.CheckPathExists(opts.input) {
				return fmt.Errorf("specified path does not exist: %s", opts.input)
			}

			return processFile(cmd.OutOrStdout(), opts.input)
		},
	}
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	rootCmd.PersistentFlags().StringVarP(&opts.input, "input", "i", "", "Input to parse")

	return rootCmd
}

func processFile(out io.Writer, filePath string) error {
	content, err := utils.ReadInput(filePath)
	if err != nil {
		return err
	}

	for _, parser := range parsers.DefaultParsers() {
		if !parser.IsCompatible(content) {
			continue
		}

		parsedResult, err := parser.Parse(content)
		if err != nil {
			return fmt.Errorf("%s parser failed: %w", parser.Name(), err)
		}

		if _, err := fmt.Fprintf(out, "Parser %s is compatible!\n", parser.Name()); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, parsedResult); err != nil {
			return err
		}
		return nil
	}

	_, err = fmt.Fprintln(out, "No compatible parser found for the file.")
	return err
}
