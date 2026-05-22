package risk

// thresholds.go defines the MIT / paid-feed product line.
//
// Changing any constant in this file changes what is free vs.
// subscription. Coordinate with the threat-intel feed schema before
// touching -- a buyer who tuned a workflow against
// classifyRiskEvidence == "ESCALATION" must keep getting the same
// signal across point releases.
//
// The constants are deliberately exported. Operators reading
// sfw-mcp's documentation should be able to point at this file and
// see exactly where the line sits.

// RiskScoreEscalation is the per-function score above which the
// function counts toward the ESCALATION classification. The value
// matches semantic_firewall's models.RiskScoreHigh so v3-compat
// scripts that grepped "high risk" entries still trip the same
// boundary.
//
// Sources of contribution to a function's RiskScore (from the engine
// at v4.0.0):
//
//	Goroutine spawn      +15
//	Each new loop        +10
//	Each new call        +5
//	Panic introduction   +5
//	Defer introduction   +3
//	Each new branch      +2
//	Entropy delta * 3    (high-entropy literal additions)
//
// A single goroutine-add hits the threshold on its own; that is
// intentional. A goroutine appearing in a "fix typo" commit is the
// canonical deceptive-commit signal.
const RiskScoreEscalation = 15

// MaxHighRiskFunctionsReported caps how many high-risk functions
// land in RiskEvidence.HighRiskFunctions. The output goes into CI
// logs and a runaway diff (1000-file rewrite) could otherwise spill
// thousands of entries. Anything beyond the cap is summarised by
// the count fields.
const MaxHighRiskFunctionsReported = 50
