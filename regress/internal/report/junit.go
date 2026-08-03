// Package report writes JUnit XML and a Markdown summary for the
// regress suite. The schema is the de-facto Surefire-compatible
// subset that GitHub Actions, Jenkins and most CI dashboards render
// without configuration.
package report

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Case is one regress case (e.g. T1.go-vet, T2.G1-smoke, T3.stream.D-1×D-2).
type Case struct {
	Name     string
	Tier     string
	Duration time.Duration
	// Empty Failure => pass.
	Failure string
	// InvalidReason means the harness could not prove that the stimulus,
	// offered load, or oracle was valid. Invalid is always a failure.
	InvalidReason string
	// SkipReason set => the case was skipped (e.g. T5 adapter missing).
	// Skips fail by default; Optional must be explicit for a non-blocking skip.
	SkipReason string
	Optional   bool
	// Evidence records machine-produced stimulus, load, and oracle facts.
	// Writers sort keys so reports are deterministic.
	Evidence map[string]string
}

// Suite collects cases across tiers and writes the final report.
type Suite struct {
	Started time.Time
	Cases   []Case
	// Complete is set only after every case in the selected manifest has
	// been reconciled. A green but incomplete report is PARTIAL, never PASS.
	Complete bool
}

func New() *Suite { return &Suite{Started: time.Now()} }

// Add records one case outcome.
func (s *Suite) Add(c Case) { s.Cases = append(s.Cases, c) }

func (c Case) failed() bool {
	return c.Failure != "" || c.InvalidReason != "" || (c.SkipReason != "" && !c.Optional)
}

// AnyFailed reports whether any case failed, was invalid, or was
// mandatorily skipped.
func (s *Suite) AnyFailed() bool {
	for _, c := range s.Cases {
		if c.failed() {
			return true
		}
	}
	return false
}

// AnyFailedAt returns true if any case in tierPrefix failed (e.g. "T1").
func (s *Suite) AnyFailedAt(tierPrefix string) bool {
	for _, c := range s.Cases {
		if c.Tier == tierPrefix && c.failed() {
			return true
		}
	}
	return false
}

type xmlSuites struct {
	XMLName  xml.Name   `xml:"testsuites"`
	State    string     `xml:"state,attr"`
	Time     float64    `xml:"time,attr"`
	Tests    int        `xml:"tests,attr"`
	Failures int        `xml:"failures,attr"`
	Skipped  int        `xml:"skipped,attr"`
	Suites   []xmlSuite `xml:"testsuite"`
}

type xmlSuite struct {
	XMLName  xml.Name  `xml:"testsuite"`
	Name     string    `xml:"name,attr"`
	Tests    int       `xml:"tests,attr"`
	Failures int       `xml:"failures,attr"`
	Skipped  int       `xml:"skipped,attr"`
	Time     float64   `xml:"time,attr"`
	Cases    []xmlCase `xml:"testcase"`
}

type xmlCase struct {
	XMLName   xml.Name    `xml:"testcase"`
	Name      string      `xml:"name,attr"`
	Classname string      `xml:"classname,attr"`
	Time      float64     `xml:"time,attr"`
	Failure   *xmlFailure `xml:"failure,omitempty"`
	Skipped   *xmlSkipped `xml:"skipped,omitempty"`
	SystemOut string      `xml:"system-out,omitempty"`
}

type xmlFailure struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type xmlSkipped struct {
	Message string `xml:"message,attr"`
}

// WriteJUnit emits JUnit XML at path. Tier grouping = testsuite name.
func (s *Suite) WriteJUnit(path string) error {
	byTier := map[string][]Case{}
	tierOrder := []string{}
	for _, c := range s.Cases {
		if _, ok := byTier[c.Tier]; !ok {
			tierOrder = append(tierOrder, c.Tier)
		}
		byTier[c.Tier] = append(byTier[c.Tier], c)
	}

	out := xmlSuites{State: reportState(s), Time: time.Since(s.Started).Seconds()}
	for _, tier := range tierOrder {
		cs := byTier[tier]
		xs := xmlSuite{Name: tier}
		for _, c := range cs {
			xc := xmlCase{
				Name:      c.Name,
				Classname: tier,
				Time:      c.Duration.Seconds(),
			}
			xs.Tests++
			out.Tests++
			if c.InvalidReason != "" {
				xc.Failure = &xmlFailure{Message: "invalid", Body: c.InvalidReason}
				xs.Failures++
				out.Failures++
			} else if c.SkipReason != "" && c.Optional {
				xc.Skipped = &xmlSkipped{Message: c.SkipReason}
				xs.Skipped++
				out.Skipped++
			} else if c.SkipReason != "" {
				xc.Failure = &xmlFailure{Message: "mandatory case skipped", Body: c.SkipReason}
				xs.Failures++
				out.Failures++
			} else if c.Failure != "" {
				xc.Failure = &xmlFailure{Message: "failed", Body: c.Failure}
				xs.Failures++
				out.Failures++
			}
			xc.SystemOut = formatEvidence(c.Evidence, "=", "\n")
			xs.Time += c.Duration.Seconds()
			xs.Cases = append(xs.Cases, xc)
		}
		out.Suites = append(out.Suites, xs)
	}

	var buf bytes.Buffer
	if _, err := io.WriteString(&buf, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	if _, err := io.WriteString(&buf, "\n"); err != nil {
		return err
	}
	return writeAtomic(path, buf.Bytes())
}

// WriteMarkdown emits a human-readable SUMMARY.md.
func (s *Suite) WriteMarkdown(path string) error {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "# rendr regression — %s\n\n", s.Started.UTC().Format(time.RFC3339))
	fmt.Fprintf(&buf, "State: %s\n\n", reportState(s))
	fmt.Fprintf(&buf, "Total elapsed: %s\n\n", time.Since(s.Started).Round(time.Millisecond))

	byTier := map[string][]Case{}
	tierOrder := []string{}
	for _, c := range s.Cases {
		if _, ok := byTier[c.Tier]; !ok {
			tierOrder = append(tierOrder, c.Tier)
		}
		byTier[c.Tier] = append(byTier[c.Tier], c)
	}

	for _, tier := range tierOrder {
		fmt.Fprintf(&buf, "## %s\n\n", tier)
		fmt.Fprintln(&buf, "| Case | Time | Result | Evidence |")
		fmt.Fprintln(&buf, "|------|------|--------|----------|")
		for _, c := range byTier[tier] {
			result := "OK"
			if c.InvalidReason != "" {
				result = "INVALID: " + c.InvalidReason
			} else if c.SkipReason != "" && c.Optional {
				result = "SKIP (optional): " + c.SkipReason
			} else if c.SkipReason != "" {
				result = "FAIL (mandatory skip): " + c.SkipReason
			} else if c.Failure != "" {
				result = "FAIL"
			}
			evidence := escapeMarkdown(formatEvidence(c.Evidence, "=", "; "))
			fmt.Fprintf(&buf, "| %s | %s | %s | %s |\n", escapeMarkdown(c.Name), c.Duration.Round(time.Millisecond), escapeMarkdown(result), evidence)
		}
		fmt.Fprintln(&buf)
	}

	overall := strings.ToUpper(reportState(s))
	fmt.Fprintf(&buf, "**OVERALL: %s**\n", overall)
	return writeAtomic(path, buf.Bytes())
}

func reportState(s *Suite) string {
	if s.AnyFailed() {
		return "fail"
	}
	if !s.Complete {
		return "partial"
	}
	return "pass"
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err == nil {
		return nil
	}
	// Windows cannot replace an existing destination with Rename. Removing
	// the old report first leaves either the new complete file or no file;
	// it never leaves a truncated report that can masquerade as success.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}

func formatEvidence(evidence map[string]string, assignment, separator string) string {
	if len(evidence) == 0 {
		return ""
	}
	keys := make([]string, 0, len(evidence))
	for key := range evidence {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+assignment+evidence[key])
	}
	return strings.Join(parts, separator)
}

func escapeMarkdown(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}
