package evidence

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// slsaProvenanceType is the SLSA v1.0 build-provenance predicate type. An
// attestation of any other type does not evidence build provenance.
const slsaProvenanceType = "https://slsa.dev/provenance/v1"

// FromProvenance turns a SLSA build-provenance attestation into evidence records
// keyed to the given control. The input is an in-toto v1 Statement - the decoded
// DSSE payload from `cosign verify-attestation --type slsaprovenance --output
// json`. One record is produced per attested subject (the built artifact).
//
// A subject is satisfied only when the statement is a SLSA provenance
// attestation AND its builder identity matches expectedBuilder, i.e. the
// artifact was built by the trusted pipeline. A mismatched builder or a
// non-provenance attestation is not-satisfied: the running artifact cannot be
// tied to a trusted build, so its integrity cannot be discerned.
func FromProvenance(provenanceJSON []byte, expectedBuilder, controlID string) ([]Record, error) {
	var stmt struct {
		Subject []struct {
			Name   string `json:"name"`
			Digest struct {
				SHA256 string `json:"sha256"`
			} `json:"digest"`
		} `json:"subject"`
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			RunDetails struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
				Metadata struct {
					StartedOn  time.Time `json:"startedOn"`
					FinishedOn time.Time `json:"finishedOn"`
				} `json:"metadata"`
			} `json:"runDetails"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(provenanceJSON, &stmt); err != nil {
		return nil, err
	}

	trusted := stmt.PredicateType == slsaProvenanceType &&
		stmt.Predicate.RunDetails.Builder.ID == expectedBuilder

	observedAt := stmt.Predicate.RunDetails.Metadata.FinishedOn
	if observedAt.IsZero() {
		observedAt = stmt.Predicate.RunDetails.Metadata.StartedOn
	}

	status := oscal.StatusNotSatisfied
	if trusted {
		status = oscal.StatusSatisfied
	}

	var records []Record
	for _, sub := range stmt.Subject {
		subject := "image/" + sub.Name
		artifactRef := ""
		if sub.Digest.SHA256 != "" {
			subject = fmt.Sprintf("image/%s@sha256:%s", sub.Name, sub.Digest.SHA256)
			artifactRef = "sha256:" + sub.Digest.SHA256
		}
		records = append(records, Record{
			ControlID:   controlID,
			Subject:     subject,
			Result:      status,
			ObservedAt:  observedAt.UTC(),
			Source:      "slsa-provenance",
			ArtifactRef: artifactRef,
		})
	}
	return records, nil
}
