package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	piondtls "github.com/pion/dtls/v2"
	"github.com/plgd-dev/go-coap/v3/dtls"
	"github.com/plgd-dev/go-coap/v3/examples/dtls/pki"
	"github.com/plgd-dev/go-coap/v3/message/pool"
)

func main() {

	if len(os.Args) != 4 {
		log.Fatalf("Error server ip and port must be provided as args\n")
	}

	srvIP := os.Args[1]
	if srvIP == "" {
		log.Fatalf("Error server ip must be provided\n")
	}
	srvPort := os.Args[2]
	if srvPort == "" {
		log.Fatalf("Error server port must be provided\n")
	}

	observePath := os.Args[3]
	if observePath == "" {
		log.Fatalf("Error observe Path portmust be provided\n")
	}

	config, err := createClientConfig(context.Background())
	if err != nil {
		log.Fatalln(err)
		return
	}
	co, err := dtls.Dial(fmt.Sprintf("%s:%s", srvIP, srvPort), config)
	if err != nil {
		log.Fatalf("Error dialing: %v", err)
	}

	sync := make(chan bool)
	num := 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	obs, err := co.Observe(ctx, observePath, func(req *pool.Message) {
		log.Printf("Got %+v %s\n", req, req.Body())
		num++
		if num >= 10 {
			sync <- true
		}
	})
	if err != nil {
		log.Fatalf("Unexpected error '%v'", err)
	}
	<-sync
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	obs.Cancel(ctx)
}

func createClientConfig(ctx context.Context) (*piondtls.Config, error) {

	// open CA cert
	CABytes, err := ioutil.ReadFile("tls-client/ca-crt.pem")
	if err != nil {
		return nil, err
	}

	// client key
	keyBytes, err := ioutil.ReadFile("tls-client/client1-key.pem")
	if err != nil {
		return nil, err
	}

	// client cert
	certBytes, err := ioutil.ReadFile("tls-client/client1-crt.pem")
	if err != nil {
		return nil, err
	}

	certificate, err := pki.LoadKeyAndCertificate(keyBytes, certBytes)
	if err != nil {
		return nil, err
	}

	// cert pool
	certPool, err := pki.LoadCertPool(CABytes)
	if err != nil {
		return nil, err
	}

	return &piondtls.Config{
		Certificates:         []tls.Certificate{*certificate},
		ExtendedMasterSecret: piondtls.RequireExtendedMasterSecret,
		RootCAs:              certPool,
		InsecureSkipVerify:   true,
	}, nil
}
