// SPDX-License-Identifier: BSD-3-Clause

// Command driver runs one test plan of the OpenID Foundation conformance
// suite against the bridge, through the suite's REST API -- what the
// suite's own run-test-plan.py does -- and fails if a module fails that
// expected.txt does not name, or one it names stops failing.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

var client = &http.Client{
	Timeout: 60 * time.Second,
	// The suite's own certificate is a development one.
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
}

func main() {
	suite := flag.String("suite", "https://localhost.emobix.co.uk:8443/", "the suite's base URL")
	plan := flag.String("plan", "oidcc-basic-certification-test-plan", "the test plan")
	variant := flag.String("variant", `{"server_metadata":"discovery","client_registration":"static_client"}`, "the plan's variant, JSON")
	config := flag.String("config", "", "the plan configuration (JSON file)")
	expected := flag.String("expected", "", "modules expected not to pass, one per line: name RESULT # why")
	flag.Parse()

	conf, err := os.ReadFile(*config)
	if err != nil {
		log.Fatal(err)
	}
	waitReady(*suite)

	var created struct {
		ID      string `json:"id"`
		Modules []struct {
			TestModule string         `json:"testModule"`
			Variant    map[string]any `json:"variant"`
		} `json:"modules"`
	}
	q := url.Values{"planName": {*plan}, "variant": {*variant}}
	must(call("POST", *suite+"api/plan?"+q.Encode(), conf, 201, &created))
	log.Printf("plan %s: %d modules", created.ID, len(created.Modules))

	want := readExpected(*expected)
	results := map[string]string{}
	var order []string
	for _, m := range created.Modules {
		q := url.Values{"test": {m.TestModule}, "plan": {created.ID}}
		if m.Variant != nil {
			v, _ := json.Marshal(m.Variant)
			q.Set("variant", string(v))
		}
		var run struct {
			ID string `json:"id"`
		}
		if err := call("POST", *suite+"api/runner?"+q.Encode(), nil, 201, &run); err != nil {
			results[m.TestModule] = "NOT-CREATED"
			order = append(order, m.TestModule)
			log.Printf("%s: %v", m.TestModule, err)
			continue
		}
		res := runModule(*suite, run.ID)
		results[m.TestModule] = res
		order = append(order, m.TestModule)
		fmt.Printf("%-60s %s\n", m.TestModule, res)
		if res != "PASSED" {
			printFailures(*suite, run.ID)
		}
	}

	// Compare with what is expected, both ways.
	bad := 0
	fmt.Println("\n== summary")
	for _, name := range order {
		got, exp := results[name], want[name]
		switch {
		case exp == "" && (got == "PASSED" || got == "WARNING" || got == "REVIEW" || got == "SKIPPED"):
		case exp == got:
			fmt.Printf("expected  %-50s %s\n", name, got)
		case exp == "":
			fmt.Printf("UNEXPECTED %-49s %s\n", name, got)
			bad++
		default:
			fmt.Printf("CHANGED   %-50s %s, expected %s\n", name, got, exp)
			bad++
		}
	}
	counts := map[string]int{}
	for _, r := range results {
		counts[r]++
	}
	fmt.Printf("\n%d modules: %v\n", len(results), counts)
	if bad > 0 {
		os.Exit(1)
	}
}

// runModule starts a module once the suite has configured it, and waits
// for it to finish; the suite drives the browser itself (HtmlUnit).
func runModule(suite, id string) string {
	deadline := time.Now().Add(5 * time.Minute)
	started := false
	for time.Now().Before(deadline) {
		var info struct {
			Status string `json:"status"`
			Result string `json:"result"`
		}
		if err := call("GET", suite+"api/info/"+id, nil, 200, &info); err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		switch info.Status {
		case "CONFIGURED":
			if !started {
				call("POST", suite+"api/runner/"+id, nil, 200, nil)
				started = true
			}
		case "FINISHED", "INTERRUPTED":
			if info.Result == "" {
				return info.Status
			}
			return info.Result
		}
		time.Sleep(2 * time.Second)
	}
	return "TIMEOUT"
}

// printFailures shows what the suite said went wrong.
func printFailures(suite, id string) {
	var entries []map[string]any
	if err := call("GET", suite+"api/log/"+id, nil, 200, &entries); err != nil {
		return
	}
	for _, e := range entries {
		r, _ := e["result"].(string)
		if r == "FAILURE" || r == "WARNING" || r == "REVIEW" {
			fmt.Printf("    %s %v: %v\n", r, e["src"], e["msg"])
		}
	}
}

func waitReady(suite string) {
	for i := range 60 {
		if err := call("GET", suite+"api/plan?length=1", nil, 200, nil); err == nil {
			log.Printf("suite ready after %d tries", i+1)
			return
		}
		time.Sleep(5 * time.Second)
	}
	log.Fatal("the suite never became ready")
}

func call(method, u string, body []byte, want int, out any) error {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		return fmt.Errorf("%s %s: %d %s", method, u, res.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// readExpected reads "module RESULT # why" lines.
func readExpected(path string) map[string]string {
	m := map[string]string{}
	if path == "" {
		return m
	}
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 2 && slices.Contains([]string{"FAILED", "WARNING", "REVIEW", "SKIPPED", "INTERRUPTED", "TIMEOUT"}, fields[1]) {
			m[fields[0]] = fields[1]
		}
	}
	return m
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
