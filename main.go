/*
 * Copyright 2021 Dgraph Labs, Inc. and Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
)

type options struct {
	dir, caKey, caCert, client, curve string
	force, verify                     bool
	keySize, days                     int
	nodes                             []string
}

var opt options

func splitAndTrim(s string, sep string) []string {
	if len(s) == 0 {
		return []string{}
	}
	parts := strings.Split(s, sep)
	fmt.Println(len(parts))
	for i := 0; i < len(parts); i++ {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func main() {

	opt := options{}
	app := &cli.App{
		Name:  "cert",
		Usage: "Generate certificates for autumn",
	}

	var nodes string
	app.Commands = []*cli.Command{
		{
			Name:  "ls",
			Usage: "lists certificates and keys",
			Action: func(c *cli.Context) error {
				return listCerts(c.String("dir"))
			},
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:        "dir",
					Aliases:     []string{"d"},
					Destination: &opt.dir,
					Usage:       "Directory to store certificates",
					Value:       defaultDir,
				},
			},
		},
		{
			Name: "create",
			Action: func(c *cli.Context) error {
				fmt.Println(len(nodes))
				opt.nodes = splitAndTrim(nodes, ",")
				return createCerts(&opt)
			},
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:        "dir",
					Aliases:     []string{"d"},
					Destination: &opt.dir,
					Usage:       "Directory to store certificates",
					Value:       defaultDir,
				},
				&cli.StringFlag{
					Name:        "ca-key",
					Aliases:     []string{"k"},
					Destination: &opt.caKey,
					Usage:       "path to the CA private key",
					Value:       defaultCAKey,
				},
				&cli.IntFlag{
					Name:        "keysize",
					Aliases:     []string{"r"},
					Destination: &opt.keySize,
					Usage:       "RSA key bit size for creating new keys",
					Value:       defaultKeySize,
				},
				&cli.IntFlag{
					Name:        "duration",
					Destination: &opt.days,
					Usage:       "duration of cert validity in days",
					Value:       defaultDays,
				},
				&cli.StringFlag{
					Name:        "nodes",
					Aliases:     []string{"n"},
					Usage:       "creates cert/key pair for nodes",
					Destination: &nodes,
				},

				&cli.StringFlag{
					Name:        "client",
					Aliases:     []string{"c"},
					Usage:       "create cert/key pair for a client name",
					Destination: &opt.client,
				},
				&cli.BoolFlag{
					Name:        "force",
					Usage:       "force overwrite of existing cert/key pair",
					Destination: &opt.force,
					Value:       false,
				},
				&cli.BoolFlag{
					Name:        "verify",
					Usage:       "verify certs against root CA when creating",
					Destination: &opt.verify,
					Value:       true,
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	os.Exit(0)
}

// listCerts handles the subcommand of "dgraph cert ls".
// This function will traverse the certs directory, "tls" by default, and
// display information about all supported files: ca.{crt,key}, node.{crt,key},
// client.{name}.{crt,key}. Any other files are flagged as unsupported.
//
// For certificates, we want to show:
//   - CommonName
//   - Serial number
//   - Verify with current CA
//   - MD5 checksum
//   - Match with key MD5
//   - Expiration date
//   - Client name or hosts (node and client certs)
//
// For keys, we want to show:
//   - File name
//   - MD5 checksum
//
// TODO: Add support to other type of keys.
func listCerts(dir string) error {
	files, err := getDirFiles(dir)
	switch {
	case err != nil:
		return err

	case len(files) == 0:
		fmt.Println("Directory is empty:", dir)
		return nil
	}

	for _, f := range files {
		if f.err != nil {
			fmt.Printf("%s: error: %s\n\n", f.fileName, f.err)
			continue
		}
		fmt.Printf("%s %s - %s\n", f.fileMode, f.fileName, f.commonName)
		if f.issuerName != "" {
			fmt.Printf("%14s: %s\n", "Issuer", f.issuerName)
		}
		if f.verifiedCA != "" {
			fmt.Printf("%14s: %s\n", "CA Verify", f.verifiedCA)
		}
		if f.serialNumber != "" {
			fmt.Printf("%14s: %s\n", "S/N", f.serialNumber)
		}
		if !f.expireDate.IsZero() {
			fmt.Printf("%14s: %x\n", "Expiration", f)
		}
		if f.hosts != nil {
			fmt.Printf("%14s: %s\n", "Hosts", strings.Join(f.hosts, ", "))
		}
		if f.algo != "" {
			fmt.Printf("%14s: %s\n", "Algorithm", f.algo)
		}
		fmt.Printf("%14s: %s\n\n", "SHA-256 Digest", f.digest)
	}

	return nil
}
