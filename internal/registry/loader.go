package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Load reads every registry artifact under root into a Registry. The layout
// mirrors the OSCAL controls tree:
//
//	<root>/agents/*.json
//	<root>/prompts/*.json
//	<root>/tools/*.json
//
// A missing subdirectory is treated as empty; a malformed document is an error.
func Load(root string) (Registry, error) {
	var r Registry

	if err := loadDir(filepath.Join(root, "agents"), func(data []byte) error {
		var a Agent
		if err := json.Unmarshal(data, &a); err != nil {
			return err
		}
		r.Agents = append(r.Agents, a)
		return nil
	}); err != nil {
		return Registry{}, err
	}

	if err := loadDir(filepath.Join(root, "prompts"), func(data []byte) error {
		var p Prompt
		if err := json.Unmarshal(data, &p); err != nil {
			return err
		}
		r.Prompts = append(r.Prompts, p)
		return nil
	}); err != nil {
		return Registry{}, err
	}

	if err := loadDir(filepath.Join(root, "tools"), func(data []byte) error {
		var t Tool
		if err := json.Unmarshal(data, &t); err != nil {
			return err
		}
		r.Tools = append(r.Tools, t)
		return nil
	}); err != nil {
		return Registry{}, err
	}

	return r, nil
}

// loadDir calls parse for every .json file in dir. A non-existent dir is not an
// error: an absent artifact kind simply contributes nothing to the registry.
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
