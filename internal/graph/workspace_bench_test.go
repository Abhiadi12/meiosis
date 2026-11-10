package graph_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/mindfire-test/meiosis/internal/graph"
	"github.com/mindfire-test/meiosis/pkg/crypto"
	specv1 "github.com/mindfire-test/meiosis/pkg/spec/v1"
	"github.com/mindfire-test/meiosis/pkg/storage/sqlite"
)

// BenchmarkForkAttempt measures forking a workspace that already holds files
// (NFR-1.1). The cost should not move with the workspace's size: compare the
// sub-benchmarks. It runs against a file database, as the server does.
func BenchmarkForkAttempt(b *testing.B) {
	for _, files := range []int{10, 1000} {
		b.Run(fmt.Sprintf("workspace-of-%d-files", files), func(b *testing.B) {
			backend, err := sqlite.Open(filepath.Join(b.TempDir(), "bench.db"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = backend.Close() })
			store := graph.NewStore(backend)
			keys, _ := crypto.GenerateKeyPair()
			ctx := context.Background()
			intent, err := store.CreateIntent(ctx, graph.CreateIntentParams{
				Repo: "r", Title: "t", Goal: "g", Acceptance: []specv1.Criterion{{Text: "ok"}},
				Scope: specv1.Scope{Allow: []string{"**"}, Mode: specv1.ScopeModeEnforce}, CreatedBy: "human:b",
			}, keys.PrivateKey)
			if err != nil {
				b.Fatal(err)
			}
			source, err := store.OpenAttempt(ctx, graph.OpenAttemptParams{Intent: intent.ID, Author: "agent:b"}, keys.PrivateKey)
			if err != nil {
				b.Fatal(err)
			}
			for i := range files {
				if _, err = store.WriteFile(ctx, graph.WriteParams{Attempt: source.ID, Author: "agent:b", Path: fmt.Sprintf("d%d/f%d", i%20, i), Content: []byte("x")}, keys.PrivateKey); err != nil {
					b.Fatal(err)
				}
			}
			b.ResetTimer()
			for range b.N {
				if _, err = store.ForkAttempt(ctx, graph.ForkParams{Source: source.ID, Author: "agent:b"}, keys.PrivateKey); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
