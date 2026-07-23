package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReportSaveAndSummary(t *testing.T) {
	r := &RunReport{
		RunnerId:     "run-1",
		BlockchainId: "chain-1",
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		Steps: []StepResult{
			{Name: "create_entity", SignerRole: "owner", PayloadType: "CREATE_ENTITY", TxId: "tx-1", Output: "SUCCESS"},
		},
	}

	dir := t.TempDir()
	path, err := r.Save(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("expected report in %s, got %s", dir, path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("report file not written: %v", err)
	}

	var buf bytes.Buffer
	PrintSummary(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "create_entity") || !strings.Contains(out, "tx-1") || !strings.Contains(out, "SUCCESS") {
		t.Fatalf("summary missing expected content:\n%s", out)
	}
}
