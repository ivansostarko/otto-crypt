package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"github.com/ivansostarko/otto-crypt-go/otto"
)

func usage() {
	fmt.Println("otto-demo (Go)")
	fmt.Println("USAGE:")
	fmt.Println("  text  --key-b64 <key> --message <utf8>")
	fmt.Println("  file  --key-b64 <key> --input <path> [--out-enc <path>] [--out-dec <path>] [--chunk <bytes>]")
	fmt.Println("  batch --key-b64 <key> --dir <dir> --out <dir> [--chunk <bytes>]")
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 { usage(); os.Exit(1) }
	switch os.Args[1] {
	case "text": runText()
	case "file": runFile()
	case "batch": runBatch()
	default: usage(); os.Exit(1)
	}
}

func runText() {
	fs := flag.NewFlagSet("text", flag.ExitOnError)
	keyB64 := fs.String("key-b64", os.Getenv("OTTO_RAWKEY_B64"), "Base64 32-byte key")
	msg := fs.String("message", "", "plaintext") 
	_ = fs.Parse(os.Args[2:])
	if *keyB64 == "" || *msg == "" { usage(); os.Exit(2) }
	key, err := otto.FromB64(*keyB64); if err != nil || len(key)!=32 { log.Fatalf("bad key: %v", err) }
	res, err := otto.EncryptString([]byte(*msg), key); if err != nil { log.Fatal(err) }
	fmt.Println("HEADER_B64=" + otto.B64(res.Header))
	fmt.Println("CIPHER_B64=" + otto.B64(res.CipherAndTag))
	pt, err := otto.DecryptString(res.CipherAndTag, res.Header, key); if err != nil { log.Fatal(err) }
	fmt.Println("DECRYPTED=" + string(pt))
}

func runFile() {
	fs := flag.NewFlagSet("file", flag.ExitOnError)
	keyB64 := fs.String("key-b64", os.Getenv("OTTO_RAWKEY_B64"), "Base64 32-byte key")
	in := fs.String("input", "", "input file path")
	outEnc := fs.String("out-enc", "", "output encrypted path (.otto)")
	outDec := fs.String("out-dec", "", "output decrypted path") 
	chunk := fs.Int("chunk", 1<<20, "chunk bytes")
	_ = fs.Parse(os.Args[2:])
	if *keyB64=="" || *in=="" { usage(); os.Exit(2) }
	key, err := otto.FromB64(*keyB64); if err != nil || len(key)!=32 { log.Fatalf("bad key: %v", err) }
	if *outEnc == "" { *outEnc = *in + ".otto" }
	if *outDec == "" { *outDec = *in + ".dec" }
	fmt.Printf("Encrypting %s -> %s\n", *in, *outEnc)
	if err := otto.EncryptFile(*in, *outEnc, key, *chunk); err != nil { log.Fatal(err) }
	fmt.Printf("Decrypting %s -> %s\n", *outEnc, *outDec)
	if err := otto.DecryptFile(*outEnc, *outDec, key); err != nil { log.Fatal(err) }
	fmt.Println("Done.")
}

func runBatch() {
	fs := flag.NewFlagSet("batch", flag.ExitOnError)
	keyB64 := fs.String("key-b64", os.Getenv("OTTO_RAWKEY_B64"), "Base64 32-byte key")
	dir := fs.String("dir", "", "input directory (recursively processed)")
	out := fs.String("out", "", "output directory")
	chunk := fs.Int("chunk", 1<<20, "chunk bytes")
	_ = fs.Parse(os.Args[2:])
	if *keyB64=="" || *dir=="" || *out=="" { usage(); os.Exit(2) }
	key, err := otto.FromB64(*keyB64); if err != nil || len(key)!=32 { log.Fatalf("bad key: %v", err) }
	if err := os.MkdirAll(*out, 0o775); err != nil { log.Fatal(err) }
	err = filepath.WalkDir(*dir, func(path string, d os.DirEntry, err error) error {
		if err != nil { return err }
		if d.IsDir() { return nil }
		if strings.HasSuffix(d.Name(), ".otto") { return nil }
		rel, _ := filepath.Rel(*dir, path)
		base := filepath.Base(rel)
		enc := filepath.Join(*out, base + ".otto")
		dec := filepath.Join(*out, base + ".dec")
		fmt.Printf("Encrypting %s -> %s\n", path, enc)
		if err := otto.EncryptFile(path, enc, key, *chunk); err != nil { return err }
		fmt.Printf("Decrypting %s -> %s\n", enc, dec)
		if err := otto.DecryptFile(enc, dec, key); err != nil { return err }
		return nil
	})
	if err != nil { log.Fatal(err) }
	fmt.Println("Batch complete.")
}
