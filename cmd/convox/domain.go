package main

import (
	"fmt"
	"strings"

	"github.com/convox/rack/cmd/convox/stdcli"
	"gopkg.in/urfave/cli.v1"
)

func init() {
	stdcli.RegisterCommand(cli.Command{
		Name:        "domain",
		Action:      cmdDomainList,
		Description: "manage domain names",
		Flags: []cli.Flag{
			appFlag,
			rackFlag,
		},
		Subcommands: []cli.Command{
			{
				Name:        "update",
				Description: "update a domain",
				Usage:       "<process:port> <certificate>",
				Action:      cmdDomainUpdate,
				Flags: []cli.Flag{
					appFlag,
					rackFlag,
					cli.StringFlag{
						Name:  "foo",
						Usage: "foo thing.",
					},
				},
			},
		},
	})
}

func cmdDomainList(c *cli.Context) error {
	_, app, err := stdcli.DirApp(c, ".")
	if err != nil {
		return stdcli.Error(err)
	}

	if len(c.Args()) > 0 {
		return stdcli.Error(fmt.Errorf("`convox domain` does not take arguments. Perhaps you meant `convox domain update`?"))
	}

	if c.Bool("help") {
		stdcli.Usage(c, "")
		return nil
	}

	domains, err := rackClient(c).ListDomains(app)
	if err != nil {
		return stdcli.Error(err)
	}

	t := stdcli.NewTable("DOMAIN", "EXPIRES")

	for _, ssl := range *domains {
		t.AddRow(fmt.Sprintf("%s:%d", ssl.Process, ssl.Port), ssl.Certificate, ssl.Domain, humanizeTime(ssl.Expiration))
	}

	t.Print()
	return nil
}

func cmdDomainUpdate(c *cli.Context) error {
	_, app, err := stdcli.DirApp(c, ".")
	if err != nil {
		return stdcli.Error(err)
	}

	if len(c.Args()) < 2 {
		stdcli.Usage(c, "update")
		return nil
	}

	target := c.Args()[0]

	parts := strings.Split(target, ":")

	if len(parts) != 2 {
		return stdcli.Error(fmt.Errorf("target must be process:port"))
	}

	fmt.Printf("Updating certificate... ")

	_, err = rackClient(c).UpdateSSL(app, parts[0], parts[1], c.Args()[1])
	if err != nil {
		return stdcli.Error(err)
	}

	fmt.Println("OK")
	return nil
}
