// Package report writes JUnit XML and a Markdown summary for the
// regress suite. The schema is the de-facto Surefire-compatible
// subset that GitHub Actions, Jenkins and most CI dashboards render
// without configuration.
package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Case is one regress case (e.g. T1.go-vet, T2.G1-smoke, T3.stream.D-1×D-2).
type Case struct {
	Name     string
	Tier     string
	Duration time.Duration
	// Empty Failure => pass.
	Failure string
	// SkipReason set => the case was skipped (e.g. T5 adapter missing).
	SkipReason string
}

// Suite collects cases across tiers and writes the final report.
type Suite struct {
	Started time.Time
	Cases   []Case
}

func New() *Suite { return &Suite{Started: time.Now()} }

// Add records one case outcome.
func (s *Suite) Add(c Case) { s.Cases = append(s.Cases, c) }

// AnyFailed reports whether any non-skipped case failed.
func (s *Suite) AnyFailed() bool {
	for _, c := range s.Cases {
		if c.Failure != "" {
			return true
		}
	}
	return false
}

// AnyFailedAt returns true if any case in tierPrefix failed (e.g. "T1").
func (s *Suite) AnyFailedAt(tierPrefix string) bool {
	for _, c := range s.Cases {
		if c.Tier == tierPrefix && c.Failure != "" {
			return true
		}
	}
	return false
}

type xmlSuites struct {
	XMLName    xml.Name   `xml:"testsuites"`
	Time       float64    `xml:"time,attr"`
	Tests      int        `xml:"tests,attr"`
	Failures   int        `xml:"failures,attr"`
	Skipped    int        `xml:"skipped,attr"`
	Suites     []xmlSuite `xml:"testsuite"`
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

	out := xmlSuites{Time: time.Since(s.Started).Seconds()}
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
			if c.SkipReason != "" {
				xc.Skipped = &xmlSkipped{Message: c.SkipReason}
				xs.Skipped++
				out.Skipped++
			} else if c.Failure != "" {
				xc.Failure = &xmlFailure{Message: "failed", Body: c.Failure}
				xs.Failures++
				out.Failures++
			}
			xs.Time += c.Duration.Seconds()
			xs.Cases = append(xs.Cases, xc)
		}
		out.Suites = append(out.Suites, xs)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.WriteString(f, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(f)
	enc.Indent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	_, err = io.WriteString(f, "\n")
	return err
}

// WriteMarkdown emits a human-readable SUMMARY.md.
func (s *Suite) WriteMarkdown(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "# rendr regression — %s\n\n", s.Started.UTC().Format(time.RFC3339))
	fmt.Fprintf(f, "Total elapsed: %s\n\n", time.Since(s.Started).Round(time.Millisecond))

	byTier := map[string][]Case{}
	tierOrder := []string{}
	for _, c := range s.Cases {
		if _, ok := byTier[c.Tier]; !ok {
			tierOrder = append(tierOrder, c.Tier)
		}
		byTier[c.Tier] = append(byTier[c.Tier], c)
	}

	for _, tier := range tierOrder {
		fmt.Fprintf(f, "## %s\n\n", tier)
		fmt.Fprintln(f, "| Case | Time | Result |")
		fmt.Fprintln(f, "|------|------|--------|")
		for _, c := range byTier[tier] {
			result := "OK"
			if c.SkipReason != "" {
				result = "SKIP: " + c.SkipReason
			} else if c.Failure != "" {
				result = "FAIL"
			}
			fmt.Fprintf(f, "| %s | %s | %s |\n", c.Name, c.Duration.Round(time.Millisecond), result)
		}
		fmt.Fprintln(f)
	}

	overall := "PASS"
	if s.AnyFailed() {
		overall = "FAIL"
	}
	fmt.Fprintf(f, "**OVERALL: %s**\n", overall)
	return nil
}
