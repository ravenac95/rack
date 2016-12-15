package main

import (
    "log"

    "golang.org/x/net/context"

    "github.com/docker/libcompose/docker"
    "github.com/docker/libcompose/docker/ctx"
    "github.com/docker/libcompose/project"
    "github.com/docker/libcompose/project/options"

    "github.com/convox/rack/cmd/convox/stdcli"
    "gopkg.in/urfave/cli.v1"

)

func init() {
    stdcli.RegisterCommand(cli.Command{
        Name:        "config",
        Description: "examine configuration for an app",
        Usage:       "[service] [command]",
        Action:      cmdConfig,
        Flags: []cli.Flag{
            cli.StringFlag{
                Name:  "file, f",
                Value: "docker-compose.yml",
                Usage: "path to an alternate docker compose manifest file",
            },
            cli.BoolFlag{
                Name:  "no-cache",
                Usage: "Pull fresh image dependencies",
            },
            cli.IntFlag{
                Name:  "shift",
                Usage: "shift allocated port numbers by the given amount",
            },
            cli.BoolFlag{
                Name:  "no-sync",
                Usage: "do not synchronize local file changes into the running containers",
            },
        },
    })
}


//func main() {
func cmdConfig(c *cli.Context) error {
    project, err := docker.NewProject(&ctx.Context{
        Context: project.Context{
            ComposeFiles: []string{"docker-compose.yml"},
            ProjectName:  "my-compose",
        },
    }, nil)

    if err != nil {
        log.Fatal(err)
		return stdcli.Error(err)
    }

    err = project.Up(context.Background(), options.Up{})

    if err != nil {
        log.Fatal(err)
		return stdcli.Error(err)
    }
	return err
}
