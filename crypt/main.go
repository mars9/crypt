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

var (
	decrypt = flag.Bool("d", false, "decrypt infile to oufile")
	file    = flag.String("f", "", "file containing passphrase")
)

func passphrase() ([]byte, error) {
	name := os.Getenv("CRYPTPASSPHRASE")
	if *file != "" {
		name = *file
	}
	if name != "" {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		b := make([]byte, 256)
		n, err := f.Read(b)
		if err != nil {
			return nil, err
		}
		b = b[0:n]
		if b[len(b)-1] == '\n' {
			b = b[0 : len(b)-1]
		}
		return b, nil
	}

	password, err := passwd.GetPasswd("Enter passphrase: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "get passphrase: %v\n", err)
		os.Exit(3)
	}

	if !*decrypt {
		confirm, err := passwd.GetPasswd("Confirm passphrase: ")
		if err != nil {
			return nil, fmt.Errorf("get passphrase: %v\n", err)
		}
		if !bytes.Equal(password, confirm) {
			return nil, fmt.Errorf("Passphrase mismatch, try again.")
		}
	}
	return password, nil
}

func main() {
	flag.Usage = usage
	flag.Parse()
	narg := flag.NArg()
	if narg > 2 {
		usage()
	}
	if runtime.GOOS == "windows" && narg == 0 {
		usage()
	}

	password, err := passphrase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(3)
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

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
