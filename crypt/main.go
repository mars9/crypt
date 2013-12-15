package main

import (
	"bytes"
	"crypto/sha1"
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/mars9/crypt"
	"github.com/mars9/passwd"
)

func main() {
	decrypt := flag.Bool("d", false, "decrypt infile to oufile")
	flag.Usage = usage
	flag.Parse()
	narg := flag.NArg()
	if narg > 2 {
		usage()
	}
	if runtime.GOOS == "windows" && narg == 0 {
		usage()
	}

	password, err := passwd.GetPasswd("Enter passphrase: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "get passphrase: %v\n", err)
		os.Exit(3)
	}

	if !*decrypt {
		confirm, err := passwd.GetPasswd("Confirm passphrase: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "get passphrase: %v\n", err)
			os.Exit(3)
		}
		if !bytes.Equal(password, confirm) {
			fmt.Fprintln(os.Stderr, "Passphrase mismatch, try again.")
			os.Exit(3)
		}
	}

	in := os.Stdin
	out := os.Stdout
	if narg > 0 {
		in, err = os.Open(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "open %s: %v\n", flag.Arg(0), err)
			os.Exit(1)
		}
		defer in.Close()
		if narg == 2 {
			out, err = os.Create(flag.Arg(1))
			if err != nil {
				fmt.Fprintf(os.Stderr, "create %s: %v\n", flag.Arg(1), err)
				os.Exit(1)
			}
			defer func() {
				if err := out.Sync(); err != nil {
					fmt.Fprintf(os.Stderr, "sync %s: %v\n", flag.Arg(1), err)
					os.Exit(1)
				}
				if err := out.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "sync %s: %v\n", flag.Arg(1), err)
					os.Exit(1)
				}
			}()
		}
	}

	c := &crypt.Crypter{
		HashFunc: sha1.New,
		HashSize: sha1.Size,
		Key:      crypt.NewPbkdf2Key(password, 32),
	}

	if !*decrypt {
		if err := c.Encrypt(out, in); err != nil {
			fmt.Fprintf(os.Stderr, "encrypt: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := c.Decrypt(out, in); err != nil {
			fmt.Fprintf(os.Stderr, "decrypt: %v\n", err)
			os.Exit(1)
		}
	}
}

func usage() {
	if runtime.GOOS == "windows" {
		fmt.Fprintf(os.Stderr, "Usage: %s [-d] infile [outfile]\n", os.Args[0])
	} else {
		fmt.Fprintf(os.Stderr, "Usage: %s [-d] [infile] [[outfile]]\n", os.Args[0])
	}
	fmt.Fprint(os.Stderr, usageMsg)
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
	os.Exit(2)
}

const usageMsg = `
Files are encrypted with AES (Rijndael) in cipher block counter mode
(CTR) and authenticate with HMAC-SHA. Encryption and HMAC keys are
derived from passphrase using PBKDF2.

If outfile is not specified, the de-/encrypted data is written to the
standard output and if infile is not specified, the de-/encrypted data
is read from standard input (reading standard input is not available
on windows).
`
