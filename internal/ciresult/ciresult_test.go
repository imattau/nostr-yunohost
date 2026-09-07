package ciresult

import (
	"strings"
	"testing"
)

func validResult() Result {
	return Result{
		Schema:     CurrentSchema,
		AppID:      "ditto",
		Repository: "https://github.com/example/ditto_ynh",
		Commit:     strings.Repeat("a", 40),
		Manifest:   "sha256:" + strings.Repeat("0", 64),
		Content:    "sha256:" + strings.Repeat("1", 64),
		Checks: map[string]string{
			"yunohost_lint": "pass",
			"shellcheck":    "pass",
			"secret_scan":   "pass",
		},
		Result: "pass",
	}
}

func TestParseValidResult(t *testing.T) {
	data, err := validResult().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	result, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if result.AppID != "ditto" || result.Result != "pass" || result.Checks["shellcheck"] != "pass" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestParseRejectsWrongSchema(t *testing.T) {
	r := validResult()
	r.Schema = 2
	data, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err == nil {
		t.Fatal("Parse() accepted an unsupported schema version")
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	if _, err := Parse([]byte("not json")); err == nil {
		t.Fatal("Parse() accepted malformed JSON")
	}
}

func TestValidateRejectsMissingChecks(t *testing.T) {
	r := validResult()
	r.Checks = nil
	if err := r.Validate(); err == nil {
		t.Fatal("Validate() accepted a result with no checks")
	}
}

func TestValidateRejectsBadCheckOutcome(t *testing.T) {
	r := validResult()
	r.Checks["shellcheck"] = "maybe"
	if err := r.Validate(); err == nil {
		t.Fatal("Validate() accepted an invalid check outcome")
	}
}

func TestValidateRejectsBadOverallResult(t *testing.T) {
	r := validResult()
	r.Result = "maybe"
	if err := r.Validate(); err == nil {
		t.Fatal("Validate() accepted an invalid overall result")
	}
}

func TestValidateRejectsBadAppID(t *testing.T) {
	r := validResult()
	r.AppID = "Not_Valid!"
	if err := r.Validate(); err == nil {
		t.Fatal("Validate() accepted an invalid app_id")
	}
}

func TestValidateRejectsNonHTTPSRepository(t *testing.T) {
	r := validResult()
	r.Repository = "git://github.com/example/ditto_ynh"
	if err := r.Validate(); err == nil {
		t.Fatal("Validate() accepted a non-HTTPS repository")
	}
}

func TestValidateRejectsBadHashFormat(t *testing.T) {
	r := validResult()
	r.Manifest = "md5:abc"
	if err := r.Validate(); err == nil {
		t.Fatal("Validate() accepted a non-sha256 manifest hash")
	}
}

func TestValidateRejectsBadCommit(t *testing.T) {
	r := validResult()
	r.Commit = "not-a-commit"
	if err := r.Validate(); err == nil {
		t.Fatal("Validate() accepted an invalid commit")
	}
}
