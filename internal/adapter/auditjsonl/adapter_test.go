package auditjsonl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAuditJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	content := `{"ts":"2026-08-24T13:22:07.651838+00:00","audit":true,"principal":"internal-enrollment-desk","tenant":"internal","gateway":"onboarding","tool":"enroll_create_invite","decision":"ALLOWED","detail":"","request_id":"ccbdf54e2a3e"}
not-json
{"ts":"2026-08-24T13:26:14.342680+00:00","audit":true,"principal":"internal-enrollment-desk","tenant":"-","gateway":"onboarding","tool":"-","decision":"ONBOARD_APPROVED_IDENTITY","detail":"app=OBR actor=client","request_id":""}
{"ts":"2026-08-24T13:27:00Z","audit":true,"principal":"client","tenant":"client","gateway":"pm-gateway","tool":"pm_delete","decision":"DENIED","detail":"policy","request_id":"req-2"}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	trace, err := (Adapter{}).Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if trace.Session.Harness != "audit-jsonl" || trace.Session.EventCount != 3 {
		t.Fatalf("session = %#v", trace.Session)
	}
	if trace.Events[0].Action != "other" || trace.Events[0].IsError {
		t.Fatalf("allowed event = %#v", trace.Events[0])
	}
	if !trace.Events[2].IsError || trace.Events[2].Action != "verify" {
		t.Fatalf("denied event = %#v", trace.Events[2])
	}
	if trace.Events[1].Targets[0].Path != "audit/-/internal-enrollment-desk/onboarding/-/ONBOARD_APPROVED_IDENTITY" {
		t.Fatalf("target = %#v", trace.Events[1].Targets)
	}
}

func TestRejectsNonAuditJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(path, []byte(`{"type":"user"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Adapter{}).Parse(path); err == nil {
		t.Fatal("Parse accepted a non-audit JSONL file")
	}
}
