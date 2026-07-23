package identity

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type StepResult struct {
	Name        string `json:"name"`
	SignerRole  string `json:"signerRole"`
	PayloadType string `json:"payloadType"`
	TxId        string `json:"txId"`
	Status      string `json:"status"`
	Output      string `json:"output"`
	Error       string `json:"error,omitempty"`
}

type RunReport struct {
	RunnerId     string       `json:"runnerId"`
	BlockchainId string       `json:"blockchainId"`
	StartTime    time.Time    `json:"startTime"`
	EndTime      time.Time    `json:"endTime"`
	Steps        []StepResult `json:"steps"`
	Failed       bool         `json:"failed"`
}

// Save writes the report as indented JSON to outputDir and returns the path.
func (r *RunReport) Save(outputDir string) (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(outputDir, fmt.Sprintf("identity_run_%s.json", r.RunnerId))
	if err := os.WriteFile(path, b, 0644); err != nil {
		return "", err
	}
	return path, nil
}

// PrintSummary writes a human-readable summary of the run.
func PrintSummary(w io.Writer, r *RunReport) {
	fmt.Fprintf(w, "\n=== Identity Lifecycle Run %s ===\n", r.RunnerId)
	fmt.Fprintf(w, "Blockchain: %s\n", r.BlockchainId)
	for _, s := range r.Steps {
		status := s.Output
		if status == "" {
			status = s.Status
		}
		line := fmt.Sprintf("  [%-12s] %-36s tx=%s %s", s.SignerRole, s.Name, s.TxId, status)
		if s.Error != "" {
			line += "  ERROR: " + s.Error
		}
		fmt.Fprintln(w, line)
	}
	result := "SUCCESS"
	if r.Failed {
		result = "FAILED"
	}
	fmt.Fprintf(w, "Result: %s (%d steps, %s)\n", result, len(r.Steps), r.EndTime.Sub(r.StartTime))
	fmt.Fprintln(w, "================================")
}
