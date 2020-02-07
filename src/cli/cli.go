package main

import (
	"os"

	"github.com/dappnode/dddns/dddns"
	"github.com/dappnode/dddns/flags"
	"github.com/dappnode/dddns/log"

	"github.com/urfave/cli"
)

var appFlags = []cli.Flag{
	flags.BootstrapNode,
	flags.DataDir,
	flags.Port,
	flags.ProtocolID,
	flags.PublicKey,
}

func startNode(ctx *cli.Context) error {
	dddnsNode := dddns.NewDDDNS(ctx)
	// Propagate errors here:
	// dddnsNode, err := dddns.NewDDDNS(ctx)
	// if err != nil {
	// 	return err
	// }
	dddnsNode.Start()
	return nil
}

func noArgs(ctx *cli.Context) error {
	cli.ShowAppHelp(ctx)
	return cli.NewExitError("no commands provided", 2)
}

func main() {
	log.InitLogger("info", "stdout")

	app := cli.NewApp()
	app.Name = "dddns"
	app.Version = dddns.VERSION
	app.Action = noArgs
	// Commands here
	app.Commands = []cli.Command{
		{
			Name:     "daemon",
			Category: "daemon",
			Usage:    "Starts DDDNS in daemon mode",
			Action: func(ctx *cli.Context) error {
				dddnsNode := dddns.NewDDDNS(ctx)
				dddnsNode.Start()
				dddnsNode.StartDaemon()

				return nil

			},
		},
		{
			Name:     "client",
			Category: "client",
			Usage:    "Starts DDDNS in client mode",
			Action: func(ctx *cli.Context) error {
				if len(ctx.GlobalString(flags.PublicKey.Name)) == 0 {
					log.Error("No target provided")
					return nil
				}
				dddnsNode := dddns.NewDDDNS(ctx)
				dddnsNode.Start()
				dddnsNode.Resolve(ctx.GlobalString(flags.PublicKey.Name))
				return nil
			},
			Flags: []cli.Flag{
				flags.PublicKey,
			},
		},
	}

	app.Flags = appFlags

	if err := app.Run(os.Args); err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

}
