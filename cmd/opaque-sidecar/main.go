// Command opaque-sidecar runs the OPAQUE (RFC 9807) server side for the
// AgentSecrets control plane.
//
// Django owns accounts and persistence; this process owns the OPAQUE server
// key material and the protocol math. It is stateless across requests: every
// call carries the client record or the server state blob from the previous
// call, so the sidecar can restart freely and scale horizontally.
//
// The protocol logic lives in pkg/sidecar so the same handler can be served
// from this loopback binary or from a serverless function.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/bytemare/opaque"

	"github.com/The-17/agentsecrets/pkg/sidecar"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8790", "listen address (loopback only)")
	devGenerateKeys := flag.Bool("dev-generate-keys", false,
		"generate throwaway key material when OPAQUE_SERVER_KEY_MATERIAL is unset (local development only)")
	printKeys := flag.Bool("print-keys", false,
		"print a fresh key material value for OPAQUE_SERVER_KEY_MATERIAL and exit")
	flag.Parse()

	if *printKeys {
		conf := opaque.DefaultConfiguration()
		skm, err := sidecar.GenerateKeyMaterial(conf)
		if err != nil {
			log.Fatal(err)
		}
		printable, err := sidecar.FormatKeyMaterial(skm)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(printable)
		return
	}

	s, err := sidecar.New(*devGenerateKeys)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              *addr,
		Handler:           s.Mux(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	host, port, _ := net.SplitHostPort(*addr)
	if host != "127.0.0.1" && host != "localhost" && host != "" {
		log.Fatalf("refusing to bind non-loopback address %q: the sidecar is internal only", host)
	}
	log.Printf("opaque sidecar listening on %s", net.JoinHostPort(host, port))
	log.Fatal(server.ListenAndServe())
}
