package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/thelicato/parsex"
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

			return processFile(cmd.OutOrStdout(), opts.input)
		},
	}
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	rootCmd.PersistentFlags().StringVarP(&opts.input, "input", "i", "", "Input to parse")

	return rootCmd
}

func processFile(out io.Writer, filePath string) error {
	result, err := parsex.ParseFile(filePath)
	if errors.Is(err, parsex.ErrNoCompatibleParser) {
		_, err = fmt.Fprintln(out, "No compatible parser found for the file.")
		return err
	}
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintf(out, "Parser %s is compatible!\n", result.Parser); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, result.Data)
	return err
}
