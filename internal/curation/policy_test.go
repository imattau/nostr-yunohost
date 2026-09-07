package curation

import (
	"testing"

	"github.com/imattau/nostr-yunohost/internal/protocol"
	"github.com/nbd-wtf/go-nostr"
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

func TestTrustedEndorsementCountCountsDistinctCurators(t *testing.T) {
	// Trust membership is enforced upstream by Accept before an endorsement
	// ever reaches Store.endorsements (see Store.IngestEndorsement); by the
	// time endorsements reach TrustedEndorsementCount/SelectCanonical, only
	// distinct-curator counting and claim filtering remain to do.
	publisher := "6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3"
	curatorA := "6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3"
	curatorB := "68680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b5"
	policy, err := NewPolicy([]string{curatorA, curatorB}, 2)
	if err != nil {
		t.Fatal(err)
	}
	endorsements := []Endorsement{
		{Publisher: publisher, AppID: "same_app", Curator: curatorA, Claim: "tested"},
		{Publisher: publisher, AppID: "same_app", Curator: curatorB, Claim: "recommend"},
		// A duplicate claim from the same curator must not double-count.
		{Publisher: publisher, AppID: "same_app", Curator: curatorA, Claim: "recommend"},
		// A non-curation claim must not count.
		{Publisher: publisher, AppID: "same_app", Curator: curatorA, Claim: "spam"},
	}
	if count := policy.TrustedEndorsementCount(publisher, "same_app", endorsements); count != 2 {
		t.Fatalf("expected 2 distinct-curator endorsements, got %d", count)
	}
	if count := policy.TrustedEndorsementCount(publisher, "other_app", endorsements); count != 0 {
		t.Fatalf("expected 0 endorsements for an unrelated app, got %d", count)
	}
}

func TestEndorsementCountsMatchesTrustedEndorsementCount(t *testing.T) {
	publisherA := "6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3"
	publisherB := "68680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b5"
	curatorA := publisherA
	curatorB := publisherB
	policy, err := NewPolicy([]string{curatorA, curatorB}, 1)
	if err != nil {
		t.Fatal(err)
	}
	endorsements := []Endorsement{
		{Publisher: publisherA, AppID: "app_a", Curator: curatorA, Claim: "tested"},
		{Publisher: publisherA, AppID: "app_a", Curator: curatorB, Claim: "recommend"},
		{Publisher: publisherB, AppID: "app_b", Curator: curatorA, Claim: "tested"},
	}
	counts := policy.EndorsementCounts(endorsements)
	if got := counts[publisherA+"\x00"+"app_a"]; got != 2 {
		t.Fatalf("expected 2 for app_a, got %d", got)
	}
	if got := counts[publisherB+"\x00"+"app_b"]; got != 1 {
		t.Fatalf("expected 1 for app_b, got %d", got)
	}
	if got := counts[publisherA+"\x00"+"app_a"]; got != policy.TrustedEndorsementCount(publisherA, "app_a", endorsements) {
		t.Fatalf("EndorsementCounts and TrustedEndorsementCount disagree: %d vs %d", got, policy.TrustedEndorsementCount(publisherA, "app_a", endorsements))
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
