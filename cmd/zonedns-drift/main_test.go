package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jenting/zonedns/internal/drift"
)

func TestPrintReportCleanExitsZero(t *testing.T) {
	var buf bytes.Buffer
	if code := printReport(&buf, drift.Compare(nil, nil), nil, drift.HostLabel, false); code != exitClean {
		t.Errorf("exit code = %d, want %d", code, exitClean)
	}
	if !strings.Contains(buf.String(), "No drift") {
		t.Errorf("output did not report a clean result:\n%s", buf.String())
	}
}

func TestPrintReportDriftExitsOne(t *testing.T) {
	var buf bytes.Buffer
	report := drift.Compare([]string{"payments.example.com"}, []string{"paymnets.example.com"})

	code := printReport(&buf, report, nil, drift.HostLabel, false)
	if code != exitDrift {
		t.Errorf("exit code = %d, want %d", code, exitDrift)
	}
	out := buf.String()
	for _, want := range []string{"payments.example.com", "paymnets.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

func TestPrintReportSkippedHiddenByDefault(t *testing.T) {
	skipped := []drift.Skipped{{Source: "prod/payments", Host: "*.example.com", Reason: drift.SkipWildcard}}

	var quiet bytes.Buffer
	printReport(&quiet, drift.Compare(nil, nil), skipped, drift.HostLabel, false)
	if strings.Contains(quiet.String(), "*.example.com") {
		t.Errorf("skipped hosts leaked into the default output:\n%s", quiet.String())
	}

	var verbose bytes.Buffer
	printReport(&verbose, drift.Compare(nil, nil), skipped, drift.HostLabel, true)
	if !strings.Contains(verbose.String(), "*.example.com") {
		t.Errorf("--show-skipped did not list the excluded host:\n%s", verbose.String())
	}
}

func TestPrintReportStatesWhatItDoesNotCheck(t *testing.T) {
	// The most dangerous way to read this report is "clean means correctly
	// configured". Names matching on both sides can still point at the wrong
	// workload — the tool does not check that, so it must say so in the report.
	var buf bytes.Buffer
	printReport(&buf, drift.Compare([]string{"a.example.com"}, nil), nil, drift.HostLabel, false)
	if !strings.Contains(buf.String(), "does not verify") {
		t.Errorf("output did not state the check's limits:\n%s", buf.String())
	}
}
