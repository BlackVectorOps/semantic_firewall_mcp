package tools

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// collectGoFiles returns the list of .go source files to analyse from
// a target that may be either a single file or a directory.
//
// Mirrors the behaviour of internal/cli.CollectFiles in the sfw repo
// so the MCP and CLI surfaces agree on what gets included: skip
// hidden dirs, skip vendor/, skip _test.go files. Stat errors on
// individual entries become per-entry warnings on stderr (matching
// the CLI) rather than aborting the whole walk -- a corrupted file
// inside a 10k-file repo should not kill an audit.
func collectGoFiles(target string) ([]string, error) {
	target = filepath.Clean(target)
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if strings.HasSuffix(target, ".go") && !isTestFile(target) {
			return []string{target}, nil
		}
		return nil, nil
	}

	var files []string
	walkErr := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip the offending entry but keep walking the rest of the
			// tree; per-file errors get surfaced when we try to read
			// each file individually.
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || (len(name) > 1 && strings.HasPrefix(name, ".")) {
				if path != target {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !isTestFile(path) {
			files = append(files, path)
		}
		return nil
	})
	return files, walkErr
}

func isTestFile(path string) bool {
	base := filepath.Base(path)
	return len(base) >= 8 && base[len(base)-8:] == "_test.go"
}
