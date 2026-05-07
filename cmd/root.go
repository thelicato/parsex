package cmd

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/thelicato/parsex/pkg/logger"
	"github.com/thelicato/parsex/pkg/parsers"
	"github.com/thelicato/parsex/pkg/types"
	"github.com/thelicato/parsex/pkg/utils"
)

var input string

func completionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion",
		Short: "Generate the autocompletion script for the specified shell",
	}
}

var rootCmd = &cobra.Command{
	Use:   "parsex",
	Short: "Parse and extract key data across multiple security tools",
	Run: func(cmd *cobra.Command, args []string) {
		if input == "" {
			fmt.Println("Error: Input is required.")
			err := cmd.Help() // Display help text
			if err != nil {
				panic(err)
			}
			return
		}
		if utils.CheckPathExists(input) {
			processFile(input)
		} else {
			fmt.Println("The specified path does not exist:", input)
		}
	},
}

func init() {
	completion := completionCmd()
	completion.Hidden = true
	rootCmd.AddCommand(completion)
	rootCmd.PersistentFlags().StringVarP(&input, "input", "i", "", "Input to parse")
	logger.SetLevel(logrus.InfoLevel)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func processFile(filepath string) {
	content, err := utils.ReadInput(filepath)
	if err != nil {
		panic(err)
	}

	parsers := []types.Parser{
		parsers.NmapXMLParser{},
		parsers.NmapGrepableParser{},
		parsers.StandardNmapParser{},
	}
	var parsedResult interface{}

	for _, parser := range parsers {
		if parser.IsCompatible(content) {
			fmt.Printf("Parser %s is compatible!\n", parser.Name())
			parsedResult, err = parser.Parse(content)
			fmt.Println(parsedResult)
			if err != nil {
				panic(err)
			}
			break
		}
	}

	if parsedResult == nil {
		fmt.Println("No compatible parser found for the file.")
		return
	}
}
