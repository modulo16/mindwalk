package auditjsonl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cosmtrek/cantoptek/internal/adapter"
	"github.com/cosmtrek/cantoptek/internal/model"
)

// Adapter reads the provider-neutral audit JSONL contract emitted by the
// central audit store. Each object is one gateway decision.
type Adapter struct {
	Dir string
}

type record struct {
	Timestamp string `json:"ts"`
	Audit     bool   `json:"audit"`
	Principal string `json:"principal"`
	Tenant    string `json:"tenant"`
	Gateway   string `json:"gateway"`
	Tool      string `json:"tool"`
	Decision  string `json:"decision"`
	Detail    string `json:"detail"`
	RequestID string `json:"request_id"`
}

func (a Adapter) Harness() string { return "audit-jsonl" }

func (a Adapter) SessionDir() string { return a.Dir }

func (a Adapter) ListSessions() ([]model.SessionMeta, error) {
	if a.Dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(a.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	metas := make([]model.SessionMeta, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".jsonl" {
			continue
		}
		meta, err := a.Summarize(filepath.Join(a.Dir, entry.Name()))
		if err == nil {
			metas = append(metas, meta)
		}
	}
	return metas, nil
}

func (a Adapter) Summarize(path string) (model.SessionMeta, error) {
	trace, err := a.parse(path, true)
	if err != nil {
		return model.SessionMeta{}, err
	}
	return model.SessionMeta{
		Key:        adapter.SessionKey(a.Harness(), path),
		ID:         trace.Session.ID,
		Harness:    a.Harness(),
		Title:      trace.Session.Title,
		Path:       path,
		StartedAt:  trace.Session.StartedAt,
		EndedAt:    trace.Session.EndedAt,
		EventCount: trace.Session.EventCount,
	}, nil
}

func (a Adapter) Parse(path string) (*model.Trace, error) { return a.parse(path, true) }

func (a Adapter) parse(path string, requireRecords bool) (*model.Trace, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	trace := &model.Trace{
		Version: 1,
		Session: model.TraceSession{
			ID:      strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
			Harness: a.Harness(),
			Path:    path,
		},
		Events: []model.Event{},
		Marks:  []model.Mark{},
	}
	recognized := false
	err = adapter.ReadJSONLines(f, func(data []byte) {
		var item record
		if json.Unmarshal(data, &item) != nil || !item.Audit || item.Timestamp == "" || item.Gateway == "" || item.Tool == "" || item.Decision == "" {
			return
		}
		recognized = true
		if trace.Session.StartedAt == "" {
			trace.Session.StartedAt = item.Timestamp
		}
		trace.Session.EndedAt = item.Timestamp
		trace.Session.Title = item.Gateway + " audit"
		trace.Events = append(trace.Events, model.Event{
			Seq:          len(trace.Events),
			Timestamp:    item.Timestamp,
			Tool:         item.Tool,
			Action:       auditAction(item.Decision),
			Targets:      []model.Target{{Path: auditPath(item), Touch: "hit", Weak: true}},
			ResultBytes:  len(item.Detail),
			IsError:      decisionFailed(item.Decision),
			OutcomeKnown: true,
			Summary:      auditSummary(item),
		})
	})
	if err != nil {
		return nil, err
	}
	if requireRecords && !recognized {
		return nil, fmt.Errorf("not an audit JSONL file: %s", path)
	}
	trace.Session.EventCount = len(trace.Events)
	trace.Stats = model.ComputeStats(trace, 0, model.ObservabilityExact)
	return trace, nil
}

func auditAction(decision string) string {
	if decisionFailed(decision) {
		return "verify"
	}
	return "other"
}

func decisionFailed(decision string) bool {
	decision = strings.ToUpper(decision)
	return strings.Contains(decision, "DENY") || strings.Contains(decision, "DENIED") || strings.Contains(decision, "REJECT") || strings.Contains(decision, "BLOCK") || strings.Contains(decision, "ERROR") || strings.Contains(decision, "FAIL")
}

func auditSummary(item record) string {
	parts := []string{item.Decision, item.Principal, item.Tenant}
	if item.Detail != "" {
		parts = append(parts, item.Detail)
	}
	if item.RequestID != "" {
		parts = append(parts, "request="+item.RequestID)
	}
	return strings.Join(parts, " | ")
}

func auditPath(item record) string {
	return strings.Join([]string{
		"audit",
		auditSegment(item.Tenant),
		auditSegment(item.Principal),
		auditSegment(item.Gateway),
		auditSegment(item.Tool),
		auditSegment(item.Decision),
	}, "/")
}

func auditSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return strings.NewReplacer("/", "_", "\\", "_", "\x00", "_").Replace(value)
}
