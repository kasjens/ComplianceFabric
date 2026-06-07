// Package loader reads OSCAL JSON documents from a controls/ directory tree into
// a validate.Bundle. The layout matches docs/02-control-authoring.md:
//
//	<root>/catalogs/*.json
//	<root>/profiles/*.json
//	<root>/component-definitions/*.json
//	<root>/crosswalks/*.json
package loader

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kasjens/ComplianceFabric/internal/crosswalk"
	"github.com/kasjens/ComplianceFabric/internal/oscal"
	"github.com/kasjens/ComplianceFabric/internal/validate"
)

// Load reads every OSCAL document under root into a bundle. A missing
// subdirectory is treated as empty; a malformed document is an error.
func Load(root string) (validate.Bundle, error) {
	var b validate.Bundle

	if err := loadDir(filepath.Join(root, "catalogs"), func(data []byte) error {
		var c oscal.Catalog
		if err := json.Unmarshal(data, &c); err != nil {
			return err
		}
		b.Catalogs = append(b.Catalogs, c)
		return nil
	}); err != nil {
		return validate.Bundle{}, err
	}

	if err := loadDir(filepath.Join(root, "profiles"), func(data []byte) error {
		var p oscal.Profile
		if err := json.Unmarshal(data, &p); err != nil {
			return err
		}
		b.Profiles = append(b.Profiles, p)
		return nil
	}); err != nil {
		return validate.Bundle{}, err
	}

	if err := loadDir(filepath.Join(root, "component-definitions"), func(data []byte) error {
		var cd oscal.ComponentDefinition
		if err := json.Unmarshal(data, &cd); err != nil {
			return err
		}
		b.ComponentDefinitions = append(b.ComponentDefinitions, cd)
		return nil
	}); err != nil {
		return validate.Bundle{}, err
	}

	if err := loadDir(filepath.Join(root, "crosswalks"), func(data []byte) error {
		var cw crosswalk.Crosswalk
		if err := json.Unmarshal(data, &cw); err != nil {
			return err
		}
		b.Crosswalks = append(b.Crosswalks, cw)
		return nil
	}); err != nil {
		return validate.Bundle{}, err
	}

	return b, nil
}

// loadDir calls parse for every .json file in dir. A non-existent dir is not an
// error: an absent model type simply contributes nothing to the bundle.
func loadDir(dir string, parse func([]byte) error) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := parse(data); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}
