// Command repo-audit checks every owned repo for secret-scan coverage:
// the Gitleaks caller workflow, push protection, and branch protection.
// Findings go to a Markdown report, never to the exit code.
// Only a hard GitHub API failure exits non-zero.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

var callerNames = map[string]bool{
	"gitleaks.yml":    true,
	"gitleaks.yaml":   true,
	"secret-scan.yml": true,
}

func api(args ...string) any {
	cmd := exec.Command("gh", append([]string{"api"}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "API ERROR: gh api %s: %s\n",
			strings.Join(args, " "), strings.TrimSpace(errb.String()))
		os.Exit(2)
	}
	var v any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		fmt.Fprintln(os.Stderr, "JSON ERROR:", err)
		os.Exit(2)
	}
	return v
}

// apiOrNone returns nil on expected failures (e.g. HTTP 404).
func apiOrNone(args ...string) any {
	cmd := exec.Command("gh", append([]string{"api"}, args...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil
	}
	var v any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		return nil
	}
	return v
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func bullets(items []string) []string {
	if len(items) == 0 {
		return []string{"- none 🎉"}
	}
	out := make([]string, 0, len(items))
	for _, n := range items {
		out = append(out, "- [ ] `"+n+"`")
	}
	return out
}

func main() {
	raw := api("user/repos", "--paginate", "--jq", "[.[]]")
	all, _ := raw.([]any)

	var missingCaller, unprotectedPush, unprotectedBranch []string
	checked, skippedPrivate := 0, 0

	for _, item := range all {
		r, _ := item.(map[string]any)
		full := str(r, "full_name")
		if !strings.HasPrefix(full, "mfenderov/") {
			continue
		}
		if archived, _ := r["archived"].(bool); archived {
			continue
		}
		parts := strings.SplitN(full, "/", 2)
		if len(parts) != 2 {
			continue
		}
		name := parts[1]
		// Private repo names must never appear in this public repo's
		// report or logs. Skip them before any per-repo output.
		if private, _ := r["private"].(bool); private {
			skippedPrivate++
			continue
		}
		if name == ".github" {
			continue // host of the shared workflows, no caller needed
		}
		checked++

		tree := apiOrNone("repos/mfenderov/"+name+"/contents/.github/workflows",
			"--jq", "[.[].name]")
		hasCaller := false
		if files, ok := tree.([]any); ok {
			for _, f := range files {
				if s, ok := f.(string); ok && callerNames[s] {
					hasCaller = true
					break
				}
			}
		}
		if !hasCaller {
			missingCaller = append(missingCaller, name)
		}

		// NOTE: the list endpoint omits security_and_analysis, fetch per repo.
		detail := api("repos/mfenderov/"+name,
			"--jq", "{push: .security_and_analysis.secret_scanning_push_protection.status, branch: .default_branch}")
		d, _ := detail.(map[string]any)
		if str(d, "push") != "enabled" {
			unprotectedPush = append(unprotectedPush, name)
		}

		branch := str(d, "branch")
		prot := apiOrNone("repos/mfenderov/"+name+"/branches/"+branch+"/protection",
			"--jq", "{force: .allow_force_pushes.enabled}")
		if prot == nil {
			unprotectedBranch = append(unprotectedBranch, name+" (no protection)")
		}
	}

	sort.Strings(missingCaller)
	sort.Strings(unprotectedPush)
	sort.Strings(unprotectedBranch)

	lines := []string{
		"## Secret-scan coverage audit",
		"",
		fmt.Sprintf("Repos checked: %d (archived and non-owned excluded).", checked),
		"",
		fmt.Sprintf("### Missing Gitleaks caller (%d)", len(missingCaller)),
	}
	lines = append(lines, bullets(missingCaller)...)
	lines = append(lines, "",
		fmt.Sprintf("### Push protection disabled (%d)", len(unprotectedPush)))
	lines = append(lines, bullets(unprotectedPush)...)
	lines = append(lines, "",
		fmt.Sprintf("### Branch protection missing, public repos (%d)", len(unprotectedBranch)))
	lines = append(lines, bullets(unprotectedBranch)...)
	lines = append(lines, "",
		fmt.Sprintf("_%d private repos skipped — names never published here._", skippedPrivate))

	reportPath := os.Getenv("REPORT_PATH")
	if reportPath == "" {
		reportPath = "report.md"
	}
	if err := os.WriteFile(reportPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "WRITE ERROR:", err)
		os.Exit(2)
	}

	problems := len(missingCaller) + len(unprotectedPush) + len(unprotectedBranch)
	fmt.Printf("MISSING_CALLER=%d\nUNPROTECTED_PUSH=%d\nUNPROTECTED_BRANCH=%d\nPROBLEMS=%d\n",
		len(missingCaller), len(unprotectedPush), len(unprotectedBranch), problems)
	if out := os.Getenv("GITHUB_OUTPUT"); out != "" {
		f, err := os.OpenFile(out, os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintf(f, "problems=%d\n", problems)
			f.Close()
		}
	}
}
