package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/untcha/age-plugin-onepassword/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Execute(ctx, os.Args[1:], cli.Options{})
	stop()
	os.Exit(code)
}
