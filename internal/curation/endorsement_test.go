package curation

import "testing"

func TestBuildAndParseEndorsement(t *testing.T) {
	publisher := "6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3"
	event, err := Build(publisher, "hello_nostr", "recommend", "tested successfully", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	endorsement, err := Parse(event)
	if err != nil {
		t.Fatal(err)
	}
	if endorsement.Publisher != publisher || endorsement.AppID != "hello_nostr" || endorsement.Claim != "recommend" {
		t.Fatalf("unexpected endorsement: %+v", endorsement)
	}
}

func TestBuildRejectsInvalidTarget(t *testing.T) {
	if _, err := Build("not-a-pubkey", "hello_nostr", "recommend", "", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err == nil {
		t.Fatal("Build() accepted an invalid publisher")
	}
}
