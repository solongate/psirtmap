package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/solongate/psirtmap/internal/cli"
	"github.com/solongate/psirtmap/internal/osv"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client := osv.NewClient(nil)
	os.Exit(cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, client))
}
