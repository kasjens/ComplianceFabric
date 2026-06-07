package evidence

import (
	"encoding/json"
	"regexp"
	"time"

	"github.com/kasjens/ComplianceFabric/internal/oscal"
)

// BannedComponent is a component the SBOM policy prohibits. An empty Version
// bans the component at every version; a set Version bans only that exact one.
type BannedComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SBOMPolicy is the authoritative statement of what an image's component
// inventory may not contain. It is kept separate from the SBOM it judges, the
// same way the eval gate is separate from the run it grades, so the artifact
// cannot vouch for itself.
type SBOMPolicy struct {
	Banned []BannedComponent `json:"banned"`
}

// FromSBOM turns a CycloneDX SBOM (as syft emits with `-o cyclonedx-json`) into
// evidence records keyed to the given control, judging the image's component
// inventory against the policy. This is the content counterpart to FromProvenance:
// provenance attests how the image was built, the SBOM attests what is inside it.
//
// An SBOM that inventories nothing is not evidence of the image's contents, so it
// yields a single not-satisfied record for the image. Otherwise every banned
// component present yields a not-satisfied record naming that component; when the
// inventory is non-empty and carries no banned component, a single satisfied
// record for the image is produced.
func FromSBOM(sbomJSON []byte, policy SBOMPolicy, controlID string) ([]Record, error) {
	var bom struct {
		Metadata struct {
			Timestamp time.Time `json:"timestamp"`
			Component struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				PURL    string `json:"purl"`
				BOMRef  string `json:"bom-ref"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
	}
	if err := json.Unmarshal(sbomJSON, &bom); err != nil {
		return nil, err
	}

	observedAt := bom.Metadata.Timestamp.UTC()
	imageSubject := "image/" + bom.Metadata.Component.Name
	if bom.Metadata.Component.Version != "" {
		imageSubject += "@" + bom.Metadata.Component.Version
	}
	// For a container image, syft records the image digest in the component's purl
	// (or bom-ref); carrying it as the artifact-ref lets a reviewer pivot from the
	// content evidence to the exact image and its transparency-log entry.
	imageRef := sha256Digest(bom.Metadata.Component.PURL + " " + bom.Metadata.Component.BOMRef)

	// An empty inventory cannot evidence what is inside the image.
	if len(bom.Components) == 0 {
		return []Record{{
			ControlID:   controlID,
			Subject:     imageSubject,
			Result:      oscal.StatusNotSatisfied,
			ObservedAt:  observedAt,
			Source:      "sbom-content",
			ArtifactRef: imageRef,
		}}, nil
	}

	var violations []Record
	for _, c := range bom.Components {
		if !isBanned(policy.Banned, c.Name, c.Version) {
			continue
		}
		violations = append(violations, Record{
			ControlID:  controlID,
			Subject:    "component/" + c.Name + "@" + c.Version,
			Result:     oscal.StatusNotSatisfied,
			ObservedAt: observedAt,
			Source:     "sbom-content",
		})
	}
	if len(violations) > 0 {
		return violations, nil
	}

	return []Record{{
		ControlID:   controlID,
		Subject:     imageSubject,
		Result:      oscal.StatusSatisfied,
		ObservedAt:  observedAt,
		Source:      "sbom-content",
		ArtifactRef: imageRef,
	}}, nil
}

// sha256DigestRe matches a sha256 content digest as it appears in a CycloneDX
// purl or bom-ref (for example "pkg:oci/mes@sha256:1f2e..."). The hex run is
// length-agnostic so it accepts both full and abbreviated digests.
var sha256DigestRe = regexp.MustCompile(`sha256:[0-9a-fA-F]+`)

// sha256Digest returns the first sha256 content digest found in s, or "" if none.
func sha256Digest(s string) string {
	return sha256DigestRe.FindString(s)
}

// isBanned reports whether a component name/version matches any policy entry. An
// entry with an empty version matches the name at every version.
func isBanned(banned []BannedComponent, name, version string) bool {
	for _, b := range banned {
		if b.Name != name {
			continue
		}
		if b.Version == "" || b.Version == version {
			return true
		}
	}
	return false
}
