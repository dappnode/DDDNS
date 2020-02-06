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

func main() {
	log.InitLogger("info", "stdout")

	app := cli.NewApp()
	app.Name = "dddns"
	app.Version = dddns.VERSION
	app.Action = startNode
	// Commands here
	app.Commands = []cli.Command{}

	app.Flags = appFlags

	if err := app.Run(os.Args); err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

}
