// Package report renders a posture view over a control bundle: for each control,
// which policies implement it and whether a profile selects it. It is the seed
// of the control-coverage view in the project roadmap (Phase 3).
package report

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/kasjens/ComplianceFabric/internal/validate"
)

// ControlCoverage is one control's coverage row.
type ControlCoverage struct {
	ControlID string
	CatalogID string
	Title     string
	Selected  bool
	PolicyIDs []string
}

// Coverage returns one row per catalog control, in catalog order.
func Coverage(b validate.Bundle) []ControlCoverage {
	selected := make(map[string]bool)
	for _, prof := range b.Profiles {
		for _, imp := range prof.Imports {
			for _, id := range imp.IncludeControls {
				selected[id] = true
			}
		}
	}

	policies := make(map[string][]string)
	for _, cd := range b.ComponentDefinitions {
		for _, m := range cd.Mappings {
			for _, impl := range m.ImplementedBy {
				policies[m.ControlID] = append(policies[m.ControlID], impl.PolicyID)
			}
		}
	}

	var rows []ControlCoverage
	for _, cat := range b.Catalogs {
		for _, c := range cat.Controls {
			rows = append(rows, ControlCoverage{
				ControlID: c.ID,
				CatalogID: cat.ID,
				Title:     c.Title,
				Selected:  selected[c.ID],
				PolicyIDs: policies[c.ID],
			})
		}
	}
	return rows
}

// Render formats coverage rows as a plain-text table with a summary line.
func Render(cov []ControlCoverage) string {
	idW := len("CONTROL")
	for _, c := range cov {
		if len(c.ControlID) > idW {
			idW = len(c.ControlID)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-*s %-12s %-9s %s\n", idW, "CONTROL", "CATALOG", "SELECTED", "POLICIES")

	selectedCount, coveredCount := 0, 0
	for _, c := range cov {
		selected := "no"
		if c.Selected {
			selected = "yes"
			selectedCount++
		}
		policies := "-"
		if len(c.PolicyIDs) > 0 {
			policies = strings.Join(c.PolicyIDs, ", ")
			coveredCount++
		}
		fmt.Fprintf(&b, "%-*s %-12s %-9s %s\n", idW, c.ControlID, c.CatalogID, selected, policies)
	}

	b.WriteString("\n")
	b.WriteString(strconv.Itoa(len(cov)) + " controls, ")
	b.WriteString(strconv.Itoa(selectedCount) + " selected, ")
	b.WriteString(strconv.Itoa(coveredCount) + " with policy coverage\n")
	return b.String()
}
