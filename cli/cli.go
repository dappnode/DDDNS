package main

import (
	"fmt"
	"github.com/dappnode/dddns/nameserver"
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
				log.InitLogger("info", "stdout")
				dddnsNode := dddns.NewDDDNS(ctx)
				dddnsNode.Start()
				if ctx.Bool("dnsenable") {
					nameserver := nameserver.NewNameServer(ctx.Int("dnsport"), ctx.String("dnshost"), dddnsNode)
					nameserver.Start()
					log.Info("DNS enabled")
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
				log.InitLogger("info", "stdout")
				//log.InitLogger("info", os.DevNull)
				pkey := ctx.String("pubkey")
				log.Infof("Name: %s", pkey)
				if len(pkey) < 52 {
					log.Error("No valid target provided")
					os.Exit(1)
				}
				dddnsNode := dddns.NewDDDNS(ctx)
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
		//log.Error("Error.")
		os.Exit(1)
	}

}
