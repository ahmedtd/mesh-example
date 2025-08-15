package main

import (
	"context"
	"flag"
	"os"

	"github.com/google/subcommands"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")

	subcommands.Register(&MeshControllerCommand{}, "")
	subcommands.Register(&DemoServerCommand{}, "")
	subcommands.Register(&HTTPSClientCommand{}, "")
	subcommands.Register(&MakeCAPoolSecretCommand{}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
