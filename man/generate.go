package main

import (
	"fmt"
	"os"

	//"github.com/convox/rack/client"
	//"github.com/convox/rack/cmd/convox/stdcli"
    "gopkg.in/urfave/cli.v1"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func addCommand(convoxCli cli.Command) *cobra.Command {
	fmt.Println("Adding command...")
	cmd := &cobra.Command{
		Use:   convoxCli.Usage,
		//Use:   convoxCli.AppHelpTemplate,
		//Use:   convoxCli.Name,
		Short: convoxCli.Description,
		//Args:  cli.NoArgs,
		//RunE:  convoxCli.runExecCommand,
	}
	fmt.Println(cmd)
	return cmd
}

func generateManPages(path string) error {
	header := &doc.GenManHeader{
		Title:   "CONVOX",
		Section: "1",
		Source:  "Convox Community",
	}

	root_cmd := &cobra.Command{Use: "convox"}

	//root_cmd.DisableAutoGenTag = true
	return doc.GenManTree(root_cmd, header, "man/man1")
}

func main() {
	path := "/tmp"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	fmt.Printf("Generating man pages into %s\n", path)
	if err := generateManPages(path); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate man pages: %s\n", err.Error())
	}
}
