// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package signingprocessor

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These tests run published RFC 8785 conformance vectors against marshalJCS,
// the step whose output every signature covers. The vectors are read from a
// pinned release of the agent-evidence-vectors package on PyPI. The wheel is
// fetched by URL and checked against its published SHA-256 before any file in
// it is read, so the corpus changes only when the pin below changes.
const (
	rfc8785VectorsWheelURL    = "https://files.pythonhosted.org/packages/4c/2e/513bae547b947b49c6cc472ca4d1a143f9c6221373b7e8b06c81b8a64504/agent_evidence_vectors-0.31.2-py3-none-any.whl"
	rfc8785VectorsWheelSHA256 = "896ac929811a1660938a6650aa1e534390cb58598a9a4f9c60ce8664f151e6c5"
	rfc8785VectorsWheelMaxLen = 64 << 20

	a2aJCSCorpusDir  = "agent_evidence_vectors/corpora/vectors-a2a-jcs-v01/"
	jcsByteCasesPath = "agent_evidence_vectors/corpora/corpora/jcs-byte-vectors/cases.json"
)

func fetchRFC8785VectorsWheel(t *testing.T) *zip.Reader {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Minute, Transport: http.DefaultTransport.(*http.Transport).Clone()}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rfc8785VectorsWheelURL, http.NoBody)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(io.LimitReader(resp.Body, rfc8785VectorsWheelMaxLen+1))
	require.NoError(t, err)
	require.LessOrEqual(t, len(body), rfc8785VectorsWheelMaxLen)
	sum := sha256.Sum256(body)
	require.Equal(t, rfc8785VectorsWheelSHA256, hex.EncodeToString(sum[:]))

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	require.NoError(t, err)
	return zr
}

func readWheelFile(t *testing.T, zr *zip.Reader, name string) []byte {
	t.Helper()
	f, err := zr.Open(name)
	require.NoError(t, err, name)
	defer f.Close()
	b, err := io.ReadAll(f)
	require.NoError(t, err, name)
	return b
}

// canonicalizeRaw sends JSON text through marshalJCS unchanged. json.RawMessage
// keeps every number token as the vector spells it, so -0 and 1e-7 reach the
// canonicalizer as written rather than as Go's reading of them.
func canonicalizeRaw(input []byte) ([]byte, error) {
	return (&signingProcessor{}).marshalJCS(json.RawMessage(input))
}

type a2aJCSManifest struct {
	Targets map[string]struct {
		Vectors int `json:"vectors"`
	} `json:"targets"`
	Vectors []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"vectors"`
}

type a2aJCSVector struct {
	ID          string          `json:"id"`
	Clause      string          `json:"clause"`
	Disposition string          `json:"disposition"`
	Input       json.RawMessage `json:"input"`
	InputRaw    *string         `json:"input_raw"`
	Expected    struct {
		CanonicalUTF8Hex string `json:"canonical_utf8_hex"`
	} `json:"expected"`
}

// TestRFC8785ConformanceVectors runs every vector of the a2a-jcs-v01 corpus
// whose clause is an RFC 8785 clause: MUST-ACCEPT vectors must produce the
// expected canonical bytes and MUST-REJECT vectors must be refused. Vectors
// for the A2A signatures-exclusion rule are not RFC 8785 and are not run.
func TestRFC8785ConformanceVectors(t *testing.T) {
	zr := fetchRFC8785VectorsWheel(t)

	var manifest a2aJCSManifest
	require.NoError(t, json.Unmarshal(readWheelFile(t, zr, a2aJCSCorpusDir+"MANIFEST.json"), &manifest))
	want := manifest.Targets["rfc8785"].Vectors
	require.Positive(t, want)

	ran := 0
	for _, entry := range manifest.Vectors {
		body := readWheelFile(t, zr, a2aJCSCorpusDir+entry.Path)
		sum := sha256.Sum256(body)
		require.Equal(t, entry.SHA256, hex.EncodeToString(sum[:]), entry.Path)

		var v a2aJCSVector
		require.NoError(t, json.Unmarshal(body, &v), entry.Path)
		if !strings.HasPrefix(v.Clause, "RFC8785-") {
			continue
		}
		ran++

		input := []byte(v.Input)
		if v.InputRaw != nil {
			input = []byte(*v.InputRaw)
		}
		t.Run(v.ID, func(t *testing.T) {
			out, err := canonicalizeRaw(input)
			switch v.Disposition {
			case "MUST-ACCEPT":
				require.NoError(t, err)
				require.Equal(t, v.Expected.CanonicalUTF8Hex, hex.EncodeToString(out))
			case "MUST-REJECT":
				require.Error(t, err, "canonical bytes produced: %q", out)
			default:
				t.Fatalf("unknown disposition %q", v.Disposition)
			}
		})
	}
	require.Equal(t, want, ran, "vectors run against the manifest's rfc8785 count")
}

type jcsByteCases struct {
	Format         string `json:"format"`
	CanonicalCases []struct {
		ID           string `json:"id"`
		Input        string `json:"input"`
		CanonicalHex string `json:"canonicalHex"`
		SHA256       string `json:"sha256"`
	} `json:"canonicalCases"`
	RejectCases []struct {
		ID       string `json:"id"`
		Input    string `json:"input"`
		JCSError string `json:"jcsError"`
	} `json:"rejectCases"`
}

// TestJCSByteVectors runs the jcs-byte-vectors cases in their JCS profile:
// each canonical case must produce its bytes and digest, and each reject case
// that names a JCS error must be refused. Reject cases that carry only an
// application-profile error (for example an integer range) are not JCS
// rejects and are not run.
func TestJCSByteVectors(t *testing.T) {
	zr := fetchRFC8785VectorsWheel(t)

	var cases jcsByteCases
	require.NoError(t, json.Unmarshal(readWheelFile(t, zr, jcsByteCasesPath), &cases))
	require.Equal(t, "jcs-byte-vectors/v1", cases.Format)
	require.NotEmpty(t, cases.CanonicalCases)

	for _, c := range cases.CanonicalCases {
		t.Run(c.ID, func(t *testing.T) {
			out, err := canonicalizeRaw([]byte(c.Input))
			require.NoError(t, err)
			require.Equal(t, c.CanonicalHex, hex.EncodeToString(out))
			sum := sha256.Sum256(out)
			require.Equal(t, c.SHA256, hex.EncodeToString(sum[:]))
		})
	}

	rejects := 0
	for _, c := range cases.RejectCases {
		if c.JCSError == "" {
			continue
		}
		rejects++
		t.Run(c.ID, func(t *testing.T) {
			out, err := canonicalizeRaw([]byte(c.Input))
			require.Error(t, err, "canonical bytes produced for %s: %q", c.JCSError, out)
		})
	}
	require.Positive(t, rejects)
}
