package evidence

import (
	"encoding/json"

	"github.com/kasjens/ComplianceFabric/internal/eval"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// FromEvalGate runs an agent version's evaluation results through the promotion
// gate and records the verdict as evidence keyed to the given control. A version
// the gate would promote is satisfied; a version the gate blocks is
// not-satisfied. The gate is the authoritative promotion policy, separate from
// the run it judges, so the evidence answers "was this version allowed to ship,
// and why" — the record auditors of a high-risk AI system ask for. One record is
// produced per run.
func FromEvalGate(runJSON []byte, gate eval.Gate, controlID string) ([]Record, error) {
	var run eval.Run
	if err := json.Unmarshal(runJSON, &run); err != nil {
		return nil, err
	}

	decision := gate.Evaluate(run)
	result := oscal.StatusSatisfied
	if !decision.Promote {
		result = oscal.StatusNotSatisfied
	}

	return []Record{{
		ControlID:  controlID,
		Subject:    "agent/" + run.Agent + "/version/" + run.Version,
		Result:     result,
		ObservedAt: run.RunAt.UTC(),
		Source:     "eval-gate",
	}}, nil
}
