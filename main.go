package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/mattn/go-isatty"
	"github.com/solongate/psirtmap/internal/cli"
	"github.com/solongate/psirtmap/internal/kev"
	"github.com/solongate/psirtmap/internal/osv"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	osvClient := osv.NewClient(nil)
	kevClient := kev.NewClient(nil)
	args := os.Args[1:]
	if len(args) == 0 && isInteractiveTerminal() {
		args = []string{"dashboard"}
	}
	os.Exit(cli.RunWithSources(ctx, args, os.Stdout, os.Stderr, osvClient, kevClient))
}

func isInteractiveTerminal() bool {
	stdin := os.Stdin.Fd()
	stdout := os.Stdout.Fd()
	stdinInteractive := isatty.IsTerminal(stdin) || isatty.IsCygwinTerminal(stdin)
	stdoutInteractive := isatty.IsTerminal(stdout) || isatty.IsCygwinTerminal(stdout)
	return stdinInteractive && stdoutInteractive
}
