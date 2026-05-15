package containerd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	c8dimages "github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/log/logtest"
	"github.com/moby/buildkit/util/attestation"
	imagetypes "github.com/moby/moby/api/types/image"
	"github.com/moby/moby/v2/daemon/server/imagebackend"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// provBlob writes content to dir/blobs/sha256/<digest> and returns its descriptor.
func provBlob(t *testing.T, dir, mt string, data []byte) ocispec.Descriptor {
	t.Helper()
	sha256Dir := filepath.Join(dir, "blobs", "sha256")
	assert.NilError(t, os.MkdirAll(sha256Dir, 0o755))
	dgst := digest.FromBytes(data)
	assert.NilError(t, os.WriteFile(filepath.Join(sha256Dir, dgst.Encoded()), data, 0o644))
	return ocispec.Descriptor{MediaType: mt, Digest: dgst, Size: int64(len(data))}
}

// provJSON marshals v and writes it as a blob.
func provJSON(t *testing.T, dir, mt string, v any) ocispec.Descriptor {
	t.Helper()
	b, err := json.Marshal(v)
	assert.NilError(t, err)
	return provBlob(t, dir, mt, b)
}

// attestationLayer describes one layer of an attestation manifest.
// When predicateType is empty the layer carries no in-toto annotation.
type attestationLayer struct {
	predicateType string
	content       []byte
}

// buildAttestationIndex writes a minimal OCI image index containing a single
// attestation manifest whose layers are given by stmts. The index blob and the
// attestation manifest blob are always written to dir; layer blobs are written
// only when writeLayerBlobs is true (pass false to simulate unavailable content).
// Returns the index descriptor (suitable for registering with an image store) and
// the synthetic platform-image digest referenced by the attestation.
func buildAttestationIndex(t *testing.T, dir string, stmts []attestationLayer, writeLayerBlobs bool) (ocispec.Descriptor, digest.Digest) {
	t.Helper()

	// Minimal empty config for the attestation manifest.
	configDesc := provBlob(t, dir, ocispec.MediaTypeImageConfig, []byte(`{}`))

	// Build layer descriptors; blobs are written only when writeLayerBlobs is set.
	var layerDescs []ocispec.Descriptor
	for _, s := range stmts {
		var desc ocispec.Descriptor
		if writeLayerBlobs {
			desc = provBlob(t, dir, "application/vnd.in-toto+json", s.content)
		} else {
			dgst := digest.FromBytes(s.content)
			desc = ocispec.Descriptor{
				MediaType: "application/vnd.in-toto+json",
				Digest:    dgst,
				Size:      int64(len(s.content)),
			}
		}
		if s.predicateType != "" {
			desc.Annotations = map[string]string{
				"in-toto.io/predicate-type": s.predicateType,
			}
		}
		layerDescs = append(layerDescs, desc)
	}

	// Write the attestation manifest blob.
	attMfst := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    layerDescs,
	}
	attMfstDesc := provJSON(t, dir, ocispec.MediaTypeImageManifest, attMfst)

	// Synthetic platform manifest digest — it need not be in the content store.
	platformDigest := digest.FromString("platform-manifest-placeholder")

	// Annotate the attestation manifest descriptor for the index.
	attMfstDesc.Annotations = map[string]string{
		attestation.DockerAnnotationReferenceType:   attestation.DockerAnnotationReferenceTypeDefault,
		attestation.DockerAnnotationReferenceDigest: platformDigest.String(),
	}
	attMfstDesc.Platform = &ocispec.Platform{OS: "unknown", Architecture: "unknown"}

	// Write the index blob.
	idx := ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{attMfstDesc},
	}
	idxDesc := provJSON(t, dir, ocispec.MediaTypeImageIndex, idx)
	idxDesc.Annotations = map[string]string{
		"io.containerd.image.name": "test:latest",
	}

	return idxDesc, platformDigest
}

// findAttestationManifest returns the first attestation-kind manifest summary in
// manifests, or fails the test if none is found.
func findAttestationManifest(t *testing.T, manifests []imagetypes.ManifestSummary) imagetypes.ManifestSummary {
	t.Helper()
	for _, m := range manifests {
		if m.Kind == imagetypes.ManifestKindAttestation {
			return m
		}
	}
	t.Fatal("no attestation manifest found in image summary")
	return imagetypes.ManifestSummary{}
}

// TestPopulateStatements verifies that image_list.go reads in-toto statement
// blobs from attestation manifest layers and stores them verbatim in
// AttestationData.Statements.
func TestPopulateStatements(t *testing.T) {
	t.Run("single_statement_populated", func(t *testing.T) {
		ctx := namespaces.WithNamespace(t.Context(), "testing")
		ctx = logtest.WithT(ctx, t)

		dir := t.TempDir()
		stmtData, _ := json.Marshal(map[string]any{
			"predicateType": "https://slsa.dev/provenance/v0.2",
			"predicate": map[string]any{
				"materials": []map[string]any{
					{"uri": "pkg:docker/library/alpine@3.18", "digest": map[string]any{"sha256": "abc123"}},
				},
			},
		})

		idxDesc, platformDigest := buildAttestationIndex(t, dir, []attestationLayer{
			{predicateType: "https://slsa.dev/provenance/v0.2", content: stmtData},
		}, true)

		cs := &blobsDirContentStore{blobs: filepath.Join(dir, "blobs", "sha256")}
		svc := fakeImageService(t, ctx, cs)
		_, err := svc.images.Create(ctx, c8dimages.Image{Name: "test:latest", Target: idxDesc})
		assert.NilError(t, err)

		all, err := svc.Images(ctx, imagebackend.ListOptions{Manifests: true})
		assert.NilError(t, err)
		assert.Assert(t, is.Len(all, 1))

		m := findAttestationManifest(t, all[0].Manifests)
		assert.Assert(t, m.AttestationData != nil)
		assert.Check(t, is.Equal(m.AttestationData.For, platformDigest))
		assert.Assert(t, is.Len(m.AttestationData.Statements, 1))

		var stmt struct {
			PredicateType string `json:"predicateType"`
			Predicate     struct {
				Materials []struct {
					URI string `json:"uri"`
				} `json:"materials"`
			} `json:"predicate"`
		}
		assert.NilError(t, json.Unmarshal(m.AttestationData.Statements[0], &stmt))
		assert.Check(t, is.Equal(stmt.PredicateType, "https://slsa.dev/provenance/v0.2"))
		assert.Check(t, is.Equal(len(stmt.Predicate.Materials), 1))
		assert.Check(t, is.Equal(stmt.Predicate.Materials[0].URI, "pkg:docker/library/alpine@3.18"))
	})

	t.Run("multiple_statements_order_preserved", func(t *testing.T) {
		ctx := namespaces.WithNamespace(t.Context(), "testing")
		ctx = logtest.WithT(ctx, t)

		dir := t.TempDir()
		v02Data, _ := json.Marshal(map[string]any{
			"predicateType": "https://slsa.dev/provenance/v0.2",
			"predicate":     map[string]any{"materials": []any{}},
		})
		v1Data, _ := json.Marshal(map[string]any{
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate": map[string]any{
				"buildDefinition": map[string]any{"resolvedDependencies": []any{}},
			},
		})

		idxDesc, _ := buildAttestationIndex(t, dir, []attestationLayer{
			{predicateType: "https://slsa.dev/provenance/v0.2", content: v02Data},
			{predicateType: "https://slsa.dev/provenance/v1", content: v1Data},
		}, true)

		cs := &blobsDirContentStore{blobs: filepath.Join(dir, "blobs", "sha256")}
		svc := fakeImageService(t, ctx, cs)
		_, err := svc.images.Create(ctx, c8dimages.Image{Name: "test:latest", Target: idxDesc})
		assert.NilError(t, err)

		all, err := svc.Images(ctx, imagebackend.ListOptions{Manifests: true})
		assert.NilError(t, err)

		m := findAttestationManifest(t, all[0].Manifests)
		assert.Assert(t, is.Len(m.AttestationData.Statements, 2))

		var s0, s1 struct {
			PredicateType string `json:"predicateType"`
		}
		assert.NilError(t, json.Unmarshal(m.AttestationData.Statements[0], &s0))
		assert.NilError(t, json.Unmarshal(m.AttestationData.Statements[1], &s1))
		assert.Check(t, is.Equal(s0.PredicateType, "https://slsa.dev/provenance/v0.2"))
		assert.Check(t, is.Equal(s1.PredicateType, "https://slsa.dev/provenance/v1"))
	})

	t.Run("layer_without_predicate_type_skipped", func(t *testing.T) {
		ctx := namespaces.WithNamespace(t.Context(), "testing")
		ctx = logtest.WithT(ctx, t)

		dir := t.TempDir()
		annotatedData, _ := json.Marshal(map[string]any{
			"predicateType": "https://slsa.dev/provenance/v0.2",
			"predicate":     map[string]any{},
		})
		unannotatedData := []byte(`{"some": "other data"}`)

		// First layer has no predicate type (should be skipped).
		// Second layer has a predicate type (should be included).
		idxDesc, _ := buildAttestationIndex(t, dir, []attestationLayer{
			{predicateType: "", content: unannotatedData},
			{predicateType: "https://slsa.dev/provenance/v0.2", content: annotatedData},
		}, true)

		cs := &blobsDirContentStore{blobs: filepath.Join(dir, "blobs", "sha256")}
		svc := fakeImageService(t, ctx, cs)
		_, err := svc.images.Create(ctx, c8dimages.Image{Name: "test:latest", Target: idxDesc})
		assert.NilError(t, err)

		all, err := svc.Images(ctx, imagebackend.ListOptions{Manifests: true})
		assert.NilError(t, err)

		m := findAttestationManifest(t, all[0].Manifests)
		assert.Assert(t, is.Len(m.AttestationData.Statements, 1),
			"only the layer with in-toto annotation should be stored")

		var stmt struct {
			PredicateType string `json:"predicateType"`
		}
		assert.NilError(t, json.Unmarshal(m.AttestationData.Statements[0], &stmt))
		assert.Check(t, is.Equal(stmt.PredicateType, "https://slsa.dev/provenance/v0.2"))
	})

	t.Run("unavailable_layers_yield_no_statements", func(t *testing.T) {
		ctx := namespaces.WithNamespace(t.Context(), "testing")
		ctx = logtest.WithT(ctx, t)

		// The attestation manifest is in the store but its layer blobs are not.
		// The daemon should silently skip unreadable layers, leaving Statements nil.
		// CheckContentAvailable also returns false because layers are missing.
		dir := t.TempDir()
		stmtData := []byte(`{"predicateType":"https://slsa.dev/provenance/v0.2"}`)

		idxDesc, _ := buildAttestationIndex(t, dir, []attestationLayer{
			{predicateType: "https://slsa.dev/provenance/v0.2", content: stmtData},
		}, false /* manifest present, layer blobs absent */)

		cs := &blobsDirContentStore{blobs: filepath.Join(dir, "blobs", "sha256")}
		svc := fakeImageService(t, ctx, cs)
		_, err := svc.images.Create(ctx, c8dimages.Image{Name: "test:latest", Target: idxDesc})
		assert.NilError(t, err)

		all, err := svc.Images(ctx, imagebackend.ListOptions{Manifests: true})
		assert.NilError(t, err)
		assert.Assert(t, is.Len(all, 1))

		m := findAttestationManifest(t, all[0].Manifests)
		assert.Check(t, is.Equal(m.Available, false))
		assert.Assert(t, m.AttestationData != nil)
		assert.Check(t, is.Nil(m.AttestationData.Statements),
			"Statements should be nil when layer blobs are not locally available")
	})
}
