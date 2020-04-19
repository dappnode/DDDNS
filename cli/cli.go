package main

import (
	"fmt"
	"os"

	"github.com/dappnode/dddns/dddns"
	"github.com/dappnode/dddns/flags"
	"github.com/dappnode/dddns/log"
	"github.com/dappnode/dddns/nameserver"

	"github.com/urfave/cli"
)

var appFlags = []cli.Flag{
	flags.BootstrapNode,
	flags.DataDir,
	flags.Port,
	flags.ProtocolID,
	flags.LogLevel,
}

func noArgs(ctx *cli.Context) error {
	cli.ShowAppHelp(ctx)
	return cli.NewExitError("No command provided! See above.", 2)
}

func main() {

	app := cli.NewApp()
	app.Name = "dddns"
	app.Version = dddns.VERSION
	app.Action = noArgs
	app.Commands = []cli.Command{
		{
			Name:     "daemon",
			Category: "daemon",
			Usage:    "Starts DDDNS in daemon mode",
			Action: func(ctx *cli.Context) error {
				log.InitLogger(ctx.GlobalString(flags.LogLevel.Name), "stdout")
				dddnsNode := dddns.NewDDDNS(ctx.GlobalInt(flags.Port.Name),
					ctx.GlobalString(flags.DataDir.Name),
					ctx.GlobalString(flags.BootstrapNode.Name),
					ctx.GlobalString(flags.ProtocolID.Name),
				)
				dddnsNode.Start()
				if ctx.Bool("dnsenable") {
					nameserver := nameserver.NewNameServer(ctx.Int(flags.DNSPort.Name), ctx.String(flags.DNSHost.Name), dddnsNode)
					nameserver.Start()
				}
				dddnsNode.StartDaemon()
				return nil

			},
			Flags: []cli.Flag{
				flags.DNSEnable,
				flags.DNSPort,
				flags.DNSHost,
			},
		},
		{
			Name:     "client",
			Category: "client",
			Usage:    "Starts DDDNS in client mode",
			Action: func(ctx *cli.Context) error {
				log.InitLogger(ctx.GlobalString(flags.LogLevel.Name), "stdout")
				pkey := ctx.String(flags.PublicKey.Name)
				if len(pkey) < 52 {
					log.Error("No valid target provided")
					os.Exit(1)
				}
				dddnsNode := dddns.NewDDDNS(ctx.GlobalInt(flags.Port.Name),
					ctx.GlobalString(flags.DataDir.Name),
					ctx.GlobalString(flags.BootstrapNode.Name),
					ctx.GlobalString(flags.ProtocolID.Name))
				dddnsNode.Start()
				ip := dddnsNode.Resolve(pkey)
				fmt.Println(ip)
				dddnsNode.Close()
				return nil
			},
			Flags: []cli.Flag{
				flags.PublicKey,
			},
		},
	}

	app.Flags = appFlags

	if err := app.Run(os.Args); err != nil {
		os.Exit(1)
	}

}
