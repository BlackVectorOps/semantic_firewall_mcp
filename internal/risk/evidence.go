// Package risk holds the deterministic, math-only side of the audit
// output. Everything an operator can verify without invoking an LLM
// lives here.
//
// IMPORTANT: this package must not import internal/provider or
// internal/agent. The compiler enforces the MIT/paid product line:
// nothing in risk_evidence depends on a provider adapter, a model,
// or an API key. If a contributor needs LLM context to compute a
// risk signal, that signal does not belong in this package.
package risk

import (
	"sort"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/models"
)

// Verdict is the deterministic classification reported in
// risk_evidence.deterministic_verdict. It is the field a math-only
// operator greps when they ignore llm_assessments entirely.
type Verdict string

const (
	// VerdictClean: no high-risk function deltas and no signature
	// hits. The diff may still modify code, but nothing crosses the
	// ESCALATION threshold and nothing matches a known-malware
	// signature.
	VerdictClean Verdict = "CLEAN"

	// VerdictEscalation: at least one function's risk score crossed
	// RiskScoreEscalation. The commit introduced new goroutines,
	// loops, calls, panics, or other control-flow shifts that a
	// vague commit message would normally hide.
	VerdictEscalation Verdict = "ESCALATION"

	// VerdictSignatureMatch: a function's topology matched an entry
	// in the signature database. Strictly dominant over ESCALATION
	// when both fire -- a named-pattern match is a stronger claim
	// than a heuristic score.
	VerdictSignatureMatch Verdict = "SIGNATURE_MATCH"
)

// FunctionRisk is one row in the HighRiskFunctions list. Mirrors the
// data points an operator would otherwise have to derive by hand
// from a DiffOutput, surfaced as a flat record.
type FunctionRisk struct {
	Function      string `json:"function"`
	File          string `json:"file,omitempty"`
	RiskScore     int    `json:"risk_score"`
	TopologyDelta string `json:"topology_delta,omitempty"`
	Status        string `json:"status"` // models.Status* constants
}

// SignatureHit is a recorded match between a function in the diff
// and an entry in the signature database. signature_hits is
// always present in the output -- empty today (no shipped DB),
// populated when the threat-intel feed is wired up. Schema
// stability across that transition is intentional.
type SignatureHit struct {
	Function      string `json:"function"`
	File          string `json:"file,omitempty"`
	SignatureID   string `json:"signature_id"`
	SignatureName string `json:"signature_name"`
	Severity      string `json:"severity"`
	Confidence    float64 `json:"confidence"`
}

// Evidence is the full deterministic side of the audit output.
// Populated entirely from api.DiffOutput plus (later) signature
// scan results -- no LLM call required.
type Evidence struct {
	AddedFunctions      int            `json:"added_functions"`
	ModifiedFunctions   int            `json:"modified_functions"`
	RemovedFunctions    int            `json:"removed_functions"`
	HighRiskFunctions   []FunctionRisk `json:"high_risk_functions"`
	SignatureHits       []SignatureHit `json:"signature_hits"`
	DeterministicVerdict Verdict       `json:"deterministic_verdict"`
}

// FromDiff builds an Evidence record from the diff output the audit
// engine pre-computed. The function is total: a nil diff produces a
// zero-value Evidence with VerdictClean (no diff means no risk to
// surface). Callers that have signature scan results should call
// AppendSignatureHits afterwards and then Classify.
func FromDiff(diff *models.DiffOutput) Evidence {
	if diff == nil {
		return Evidence{
			HighRiskFunctions: []FunctionRisk{},
			SignatureHits:     []SignatureHit{},
			DeterministicVerdict: VerdictClean,
		}
	}

	e := Evidence{
		AddedFunctions:    diff.Summary.Added,
		ModifiedFunctions: diff.Summary.Modified,
		RemovedFunctions:  diff.Summary.Removed,
		HighRiskFunctions: []FunctionRisk{},
		SignatureHits:     []SignatureHit{},
	}

	for _, fn := range diff.Functions {
		if fn.RiskScore < RiskScoreEscalation {
			continue
		}
		e.HighRiskFunctions = append(e.HighRiskFunctions, FunctionRisk{
			Function:      fn.Function,
			RiskScore:     fn.RiskScore,
			TopologyDelta: fn.TopologyDelta,
			Status:        fn.Status,
		})
	}

	// Deterministic ordering: highest score first, then by function
	// name for stable tie-breaking. Operators piping the output to
	// `diff` between runs need stable order or every CI run reads as
	// a change.
	sort.SliceStable(e.HighRiskFunctions, func(i, j int) bool {
		if e.HighRiskFunctions[i].RiskScore != e.HighRiskFunctions[j].RiskScore {
			return e.HighRiskFunctions[i].RiskScore > e.HighRiskFunctions[j].RiskScore
		}
		return e.HighRiskFunctions[i].Function < e.HighRiskFunctions[j].Function
	})

	if len(e.HighRiskFunctions) > MaxHighRiskFunctionsReported {
		e.HighRiskFunctions = e.HighRiskFunctions[:MaxHighRiskFunctionsReported]
	}

	e.DeterministicVerdict = Classify(e)
	return e
}

// Classify is the one place the MIT/paid product boundary is
// computed. Keep it pure (no side effects, no I/O) so callers can
// trust the output is a function of its input alone.
//
// Precedence rules:
//
//	any SignatureHits     -> VerdictSignatureMatch  (strictly dominant)
//	any HighRiskFunctions -> VerdictEscalation
//	otherwise             -> VerdictClean
func Classify(e Evidence) Verdict {
	if len(e.SignatureHits) > 0 {
		return VerdictSignatureMatch
	}
	if len(e.HighRiskFunctions) > 0 {
		return VerdictEscalation
	}
	return VerdictClean
}
