package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/storage/jsondb"
	"github.com/BlackVectorOps/semantic_firewall/v4/pkg/storage/pebbledb"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// statsResult mirrors the JSON shape v3's `sfw stats` printed, so the
// agent (or any consumer that already knew that contract) sees the
// same keys.
type statsResult struct {
	Database          string `json:"database"`
	Backend           string `json:"backend"`
	SignatureCount    int    `json:"signature_count"`
	TopoIndexCount    int    `json:"topology_index_count,omitempty"`
	EntropyIndexCount int    `json:"entropy_index_count,omitempty"`
	FileSizeBytes     int64  `json:"file_size_bytes"`
	Version           string `json:"version,omitempty"`
}

// NewStatsTool returns the sfw_stats tool definition and handler.
//
// sfw_stats opens a signature database (PebbleDB directory or JSON
// file) read-only and reports the metadata an agent needs to decide
// whether scanning against that DB will be useful: backend, signature
// count, index sizes, on-disk footprint.
func NewStatsTool() (mcp.Tool, server.ToolHandlerFunc) {
	tool := mcp.NewTool("sfw_stats",
		mcp.WithDescription(
			"Inspect a Semantic Firewall signature database. Returns "+
				"backend type (pebbledb or json), signature count, "+
				"topology/entropy index sizes, and on-disk byte size. "+
				"Use this to confirm a database is populated before "+
				"calling sfw_scan, or to compare two databases.",
		),
		mcp.WithString("db_path",
			mcp.Required(),
			mcp.Description("Filesystem path to the signature database. PebbleDB stores are directories; legacy JSON stores end in .json."),
		),
	)

	handler := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		dbPath, err := req.RequireString("db_path")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("db_path: %v", err)), nil
		}

		result, err := readStats(dbPath)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("sfw_stats failed", err), nil
		}

		body, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return mcp.NewToolResultErrorFromErr("sfw_stats: marshal", err), nil
		}
		return mcp.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

func readStats(dbPath string) (*statsResult, error) {
	size, _ := pathSize(dbPath)

	if strings.HasSuffix(dbPath, ".json") {
		s := jsondb.NewScanner()
		// jsondb.Scanner.Close is a no-op today, but defer-Close here
		// keeps the call shape symmetrical with the PebbleDB branch
		// below and survives any future Close implementation that
		// actually releases something.
		defer s.Close()
		if err := s.LoadDatabase(dbPath); err != nil {
			return nil, err
		}
		db := s.GetDatabase()
		return &statsResult{
			Database:       dbPath,
			Backend:        "json",
			Version:        db.Version,
			SignatureCount: len(db.Signatures),
			FileSizeBytes:  size,
		}, nil
	}

	opts := pebbledb.DefaultPebbleScannerOptions()
	opts.ReadOnly = true
	ps, err := pebbledb.NewPebbleScanner(dbPath, opts)
	if err != nil {
		return nil, err
	}
	defer ps.Close()

	stats, err := ps.Stats()
	if err != nil {
		return nil, err
	}
	return &statsResult{
		Database:          dbPath,
		Backend:           "pebbledb",
		SignatureCount:    stats.SignatureCount,
		TopoIndexCount:    stats.TopoIndexCount,
		EntropyIndexCount: stats.EntropyIndexCount,
		FileSizeBytes:     size,
	}, nil
}

// pathSize returns the on-disk byte total for a file or directory.
// PebbleDB stores are directories, so we walk; the JSON path is a
// single file and fs.Stat suffices.
func pathSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return info.Size(), nil
	}
	var total int64
	err = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	return total, err
}
