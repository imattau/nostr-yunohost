package curation

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nostr-yunohost/nostr-yunohost/internal/protocol"
)

func TestPolicySelectsEndorsedCanonicalApp(t *testing.T) {
	curatorKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	curator, _ := nostr.GetPublicKey(curatorKey)
	publisher := "6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3"
	policy, err := NewPolicy([]string{curator}, 1)
	if err != nil {
		t.Fatal(err)
	}
	event, err := Build(publisher, "same_app", "recommend", "canonical", curatorKey)
	if err != nil {
		t.Fatal(err)
	}
	endorsement, err := policy.Accept(event)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []protocol.AppDeclaration{{Publisher: publisher, AppID: "same_app"}, {Publisher: "68680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b5", AppID: "same_app"}}
	selected := policy.SelectCanonical(candidates, []Endorsement{endorsement})
	if selected == nil || selected.Publisher != publisher {
		t.Fatalf("unexpected canonical selection: %+v", selected)
	}
}

func TestPolicyLeavesTieUnresolved(t *testing.T) {
	policy, err := NewPolicy([]string{"6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []protocol.AppDeclaration{{Publisher: "6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3", AppID: "same_app"}, {Publisher: "68680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b5", AppID: "same_app"}}
	endorsements := []Endorsement{{Publisher: candidates[0].Publisher, AppID: "same_app", Curator: "curator-a", Claim: "recommend"}, {Publisher: candidates[1].Publisher, AppID: "same_app", Curator: "curator-a", Claim: "recommend"}}
	if selected := policy.SelectCanonical(candidates, endorsements); selected != nil {
		t.Fatalf("tie should remain unresolved: %+v", selected)
	}
}
