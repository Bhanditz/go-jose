/*-
 * Copyright 2014 Square Inc.
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
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sync"

	"github.com/codegangsta/cli"
	"github.com/square/go-jose"
)

func main() {
	app := cli.NewApp()
	app.Name = "jose-util"
	app.Usage = "command-line utility to deal with JOSE objects"
	app.Version = "0.0.3"
	app.Author = ""
	app.Email = ""

	runtime.GOMAXPROCS(runtime.NumCPU())

	app.Commands = []cli.Command{
		{
			Name:  "encrypt",
			Usage: "encrypt a plaintext",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "key, k",
					Usage: "Path to key file (PEM/DER)",
				},
				cli.StringFlag{
					Name:  "input, in",
					Usage: "Path to input file (stdin if missing)",
				},
				cli.StringFlag{
					Name:  "output, out",
					Usage: "Path to output file (stdout if missing)",
				},
				cli.StringFlag{
					Name:  "algorithm, alg",
					Usage: "Key management algorithm (e.g. RSA-OAEP)",
				},
				cli.StringFlag{
					Name:  "encryption, enc",
					Usage: "Content encryption algorithm (e.g. A128GCM)",
				},
				cli.BoolFlag{
					Name:  "full, f",
					Usage: "Use full serialization format (instead of compact)",
				},
			},
			Action: func(c *cli.Context) {
				keyBytes, err := ioutil.ReadFile(requiredFlag(c, "key"))
				exitOnError(err, "unable to read key file")

				pub, err := jose.LoadPublicKey(keyBytes)
				exitOnError(err, "unable to read public key")

				alg := jose.KeyAlgorithm(requiredFlag(c, "alg"))
				enc := jose.ContentEncryption(requiredFlag(c, "enc"))

				crypter, err := jose.NewEncrypter(alg, enc, pub)
				exitOnError(err, "unable to instantiate encrypter")

				input := readInput(c.String("input"), false)
				input.Scan()

				obj, err := crypter.Encrypt(input.Bytes())
				exitOnError(err, "unable to encrypt")

				var msg string
				if c.Bool("full") {
					msg = obj.FullSerialize()
				} else {
					msg, err = obj.CompactSerialize()
					exitOnError(err, "unable to serialize message")
				}

				writeOutput(c.String("output"), []byte(msg))
			},
		},
		{
			Name:  "decrypt",
			Usage: "decrypt a ciphertext",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "key, k",
					Usage: "Path to key file (PEM/DER)",
				},
				cli.StringFlag{
					Name:  "input, in",
					Usage: "Path to input file (stdin if missing)",
				},
				cli.StringFlag{
					Name:  "output, out",
					Usage: "Path to output file (stdout if missing)",
				},
				cli.BoolFlag{
					Name:  "batch",
					Usage: "Batch decrypt messages (newline-separated)",
				},
			},
			Action: func(c *cli.Context) {
				keyBytes, err := ioutil.ReadFile(requiredFlag(c, "key"))
				exitOnError(err, "unable to read private key")

				priv, err := jose.LoadPrivateKey(keyBytes)
				exitOnError(err, "unable to read private key")

				worker := func(msg []byte, future chan []byte) {
					obj, err := jose.ParseEncrypted(string(msg))
					exitOnError(err, "unable to parse message")

					plaintext, err := obj.Decrypt(priv)
					exitOnError(err, "unable to decrypt message")

					future <- plaintext
				}

				writer := func(output []byte) {
					writeOutput(c.String("output"), output)
				}

				parMap(readInput(c.String("input"), c.Bool("batch")), worker, writer)
			},
		},
		{
			Name:  "sign",
			Usage: "sign a plaintext",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "algorithm, alg",
					Usage: "Signing algorithm (e.g. PS256)",
				},
				cli.StringFlag{
					Name:  "key, k",
					Usage: "Path to key file (PEM/DER)",
				},
				cli.StringFlag{
					Name:  "input, in",
					Usage: "Path to input file (stdin if missing)",
				},
				cli.StringFlag{
					Name:  "output, out",
					Usage: "Path to output file (stdout if missing)",
				},
				cli.BoolFlag{
					Name:  "full, f",
					Usage: "Use full serialization format (instead of compact)",
				},
			},
			Action: func(c *cli.Context) {
				keyBytes, err := ioutil.ReadFile(requiredFlag(c, "key"))
				exitOnError(err, "unable to read key file")

				signingKey, err := jose.LoadPrivateKey(keyBytes)
				exitOnError(err, "unable to read private key")

				alg := jose.SignatureAlgorithm(requiredFlag(c, "algorithm"))
				signer, err := jose.NewSigner(alg, signingKey)
				exitOnError(err, "unable to make signer")

				input := readInput(c.String("input"), false)
				input.Scan()

				obj, err := signer.Sign(input.Bytes())
				exitOnError(err, "unable to sign")

				var msg string
				if c.Bool("full") {
					msg = obj.FullSerialize()
				} else {
					msg, err = obj.CompactSerialize()
					exitOnError(err, "unable to serialize message")
				}

				writeOutput(c.String("output"), []byte(msg))
			},
		},
		{
			Name:  "verify",
			Usage: "verify a signature",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "key, k",
					Usage: "Path to key file (PEM/DER)",
				},
				cli.StringFlag{
					Name:  "input, in",
					Usage: "Path to input file (stdin if missing)",
				},
				cli.StringFlag{
					Name:  "output, out",
					Usage: "Path to output file (stdout if missing)",
				},
				cli.BoolFlag{
					Name:  "batch",
					Usage: "Batch decrypt messages (newline-separated)",
				},
			},
			Action: func(c *cli.Context) {
				keyBytes, err := ioutil.ReadFile(requiredFlag(c, "key"))
				exitOnError(err, "unable to read key file")

				verificationKey, err := jose.LoadPublicKey(keyBytes)
				exitOnError(err, "unable to read private key")

				worker := func(signed []byte, future chan []byte) {
					obj, err := jose.ParseSigned(string(signed))
					exitOnError(err, "unable to parse message")

					payload, err := obj.Verify(verificationKey)
					exitOnError(err, "invalid signature")

					future <- payload
				}

				writer := func(output []byte) {
					writeOutput(c.String("output"), output)
				}

				parMap(readInput(c.String("input"), c.Bool("batch")), worker, writer)
			},
		},
		{
			Name:  "expand",
			Usage: "expand compact message to full format",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "input, in",
					Usage: "Path to input file (stdin if missing)",
				},
				cli.StringFlag{
					Name:  "output, out",
					Usage: "Path to output file (stdout if missing)",
				},
				cli.StringFlag{
					Name:  "format, f",
					Usage: "Message format (JWE/JWS, defaults to JWE)",
				},
			},
			Action: func(c *cli.Context) {
				input := readInput(c.String("input"), false)
				input.Scan()

				var serialized string
				var err error
				switch c.String("format") {
				case "", "JWE":
					var jwe *jose.JsonWebEncryption
					jwe, err = jose.ParseEncrypted(input.Text())
					if err == nil {
						serialized = jwe.FullSerialize()
					}
				case "JWS":
					var jws *jose.JsonWebSignature
					jws, err = jose.ParseSigned(input.Text())
					if err == nil {
						serialized = jws.FullSerialize()
					}
				}

				exitOnError(err, "unable to expand message")
				writeOutput(c.String("output"), []byte(serialized))
			},
		},
	}

	err := app.Run(os.Args)
	exitOnError(err, "unable to run application")
}

// Retrieve value of a required flag
func requiredFlag(c *cli.Context, flag string) string {
	value := c.String(flag)
	if value == "" {
		fmt.Fprintf(os.Stderr, "missing required flag --%s\n", flag)
		os.Exit(1)
	}
	return value
}

// Exit and print error message if we encountered a problem
func exitOnError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
}

// Read input from file or stdin
func readInput(path string, batch bool) (scanner *bufio.Scanner) {
	if path == "" {
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		file, err := os.Open(path)
		exitOnError(err, "unable to read input")
		scanner = bufio.NewScanner(file)
	}

	if !batch {
		scanner.Split(readFullInput)
	}

	return
}

func parMap(input *bufio.Scanner, worker func([]byte, chan []byte), writer func([]byte)) {
	output := make(chan chan []byte, runtime.NumCPU())
	group := sync.WaitGroup{}

	// Print outputs
	go func() {
		for {
			writer(<-<-output)
			group.Done()
		}
	}()

	// Run workers in parallel
	for input.Scan() {
		group.Add(1)
		future := make(chan []byte)
		output <- future

		// Using append to create a copy of the scanned data, otherwise we'll
		// run into trouble since bufio.Scanner will overwrite the array.
		go worker(append([]byte{}, input.Bytes()...), future)
	}

	group.Wait()
}

func readFullInput(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	} else {
		return 0, nil, nil
	}
}

// Write output to file or stdin
func writeOutput(path string, data []byte) {
	var err error

	if path != "" {
		err = ioutil.WriteFile(path, data, 0644)
	} else {
		_, err = os.Stdout.Write(data)
	}

	exitOnError(err, "unable to write output")
}
