package opaque

import (
	"testing"

	"github.com/bytemare/opaque"
)

// TestRegistrationAndLoginRoundTrips proves the exported client helpers agree
// with each other end to end. The sidecar tests own the server side; this one
// catches a broken helper before it reaches the network.
func TestRegistrationAndLoginRoundTrips(t *testing.T) {
	const (
		password     = "correct-horse-battery-staple"
		credentialID = "user@example.com"
	)

	conf := opaque.DefaultConfiguration()
	server, err := conf.Server()
	if err != nil {
		t.Fatal(err)
	}
	secret, public := conf.KeyGen()
	if err := server.SetKeyMaterial(&opaque.ServerKeyMaterial{
		PrivateKey:     secret,
		PublicKeyBytes: public.Encode(),
		OPRFGlobalSeed: conf.GenerateOPRFSeed(),
	}); err != nil {
		t.Fatal(err)
	}
	dser, err := conf.Deserializer()
	if err != nil {
		t.Fatal(err)
	}

	client, regStart, err := RegisterStart(password)
	if err != nil {
		t.Fatalf("register start: %v", err)
	}

	parsedReq, err := dser.RegistrationRequest(regStart)
	if err != nil {
		t.Fatalf("parse registration request: %v", err)
	}
	regResponse, err := server.RegistrationResponse(parsedReq, []byte(credentialID), nil)
	if err != nil {
		t.Fatalf("server registration response: %v", err)
	}

	record, err := RegisterFinish(client, regResponse.Serialize(), credentialID)
	if err != nil {
		t.Fatalf("register finish: %v", err)
	}
	regRecord, err := dser.RegistrationRecord(record)
	if err != nil {
		t.Fatalf("parse record: %v", err)
	}
	serverRecord := &opaque.ClientRecord{
		RegistrationRecord:   regRecord,
		CredentialIdentifier: []byte(credentialID),
		ClientIdentity:       []byte(credentialID),
	}

	loginClient, ke1Bytes, err := LoginStart(password)
	if err != nil {
		t.Fatalf("login start: %v", err)
	}
	ke1, err := dser.KE1(ke1Bytes)
	if err != nil {
		t.Fatalf("parse ke1: %v", err)
	}
	ke2, serverOutput, err := server.GenerateKE2(ke1, serverRecord)
	if err != nil {
		t.Fatalf("server ke2: %v", err)
	}

	ke3Bytes, _, err := LoginFinish(loginClient, EncodeB64(ke2.Serialize()), credentialID)
	if err != nil {
		t.Fatalf("login finish: %v", err)
	}
	ke3, err := dser.KE3(ke3Bytes)
	if err != nil {
		t.Fatalf("parse ke3: %v", err)
	}
	if err := server.LoginFinish(ke3, serverOutput.ClientMAC); err != nil {
		t.Fatalf("server rejected ke3: %v", err)
	}

	// A wrong password must not produce a usable KE3.
	wrongClient, wrongKE1Bytes, err := LoginStart("not-the-password")
	if err != nil {
		t.Fatalf("wrong-password login start: %v", err)
	}
	wrongKE1, err := dser.KE1(wrongKE1Bytes)
	if err != nil {
		t.Fatalf("parse wrong ke1: %v", err)
	}
	wrongKE2, _, err := server.GenerateKE2(wrongKE1, serverRecord)
	if err != nil {
		t.Fatalf("server ke2 for wrong password: %v", err)
	}
	if _, _, err := LoginFinish(wrongClient, EncodeB64(wrongKE2.Serialize()), credentialID); err == nil {
		t.Fatal("login with the wrong password succeeded")
	}
}
