package main

import (
	"bytes"
	"io/ioutil"
	"os"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard"
)

type context struct {
	Debug bool
}

type versionCmd struct {
}

type kmPrintCmd struct {
	Path string `arg required name:"path" help:"Path to the km binary file"`
}

type kmExportCmd struct {
	BIOS string `arg required name:"bios" help:"Path to the full BIOS binary file." type:"path"`
	Out  string `arg required name:"out" help:"Path to the newly generated KM binary file." type:"path"`
}

func (kmp *kmPrintCmd) Run(ctx *context) error {
	data, err := ioutil.ReadFile(kmp.Path)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(data)
	km, err := bootguard.ParseKM(reader)
	if err != nil {
		return err
	}
	km.Print()
	if km.KeyAndSignature.Signature.DataTotalSize() > 1 {
		if err := km.KeyAndSignature.Key.PrintKMPubKey(manifest.AlgSHA256); err != nil {
			return err
		}
	}
	return nil
}

func (kme *kmExportCmd) Run(ctx *context) error {
	data, err := ioutil.ReadFile(kme.BIOS)
	if err != nil {
		return err
	}
	kmfile, err := os.Create(kme.Out)
	if err != nil {
		return err
	}
	err = bootguard.WriteBGStructures(data, nil, kmfile, nil)
	if err != nil {
		return err
	}
	return nil
}

var cli struct {
	KMShow   kmPrintCmd  `cmd help:"Prints Key Manifest binary in human-readable format"`
	KMExport kmExportCmd `cmd help:"Exports KM structures from BIOS image into file"`
}
