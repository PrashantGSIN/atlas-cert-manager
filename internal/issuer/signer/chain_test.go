package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCert struct {
	cert *x509.Certificate
	key  crypto.Signer
}

var serial int64

// newTestCert creates a certificate for cn, signed by parent, or self-signed
// when parent is nil.
func newTestCert(t *testing.T, cn string, isCA bool, parent *testCert) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	signerCert, signerKey := tmpl, crypto.Signer(key)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCert{cert: cert, key: key}
}

func certs(tcs ...*testCert) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(tcs))
	for _, tc := range tcs {
		out = append(out, tc.cert)
	}
	return out
}

func subjects(certs []*x509.Certificate) []string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		out = append(out, c.Subject.CommonName)
	}
	return out
}

func TestBuildChain(t *testing.T) {
	root := newTestCert(t, "root", true, nil)
	intermediate := newTestCert(t, "intermediate", true, root)
	leaf := newTestCert(t, "leaf", false, intermediate)

	// root -> intermediate1 -> intermediate2 -> leaf2
	intermediate1 := newTestCert(t, "intermediate1", true, root)
	intermediate2 := newTestCert(t, "intermediate2", true, intermediate1)
	leaf2 := newTestCert(t, "leaf2", false, intermediate2)

	otherRoot := newTestCert(t, "other-root", true, nil)
	otherIntermediate := newTestCert(t, "other-intermediate", true, otherRoot)

	tests := map[string]struct {
		leaf          *testCert
		trustChain    []*testCert
		expectedChain []string
		expectedCA    string
		expectedError error
	}{
		"intermediate-then-root": {
			leaf:          leaf,
			trustChain:    []*testCert{intermediate, root},
			expectedChain: []string{"leaf", "intermediate"},
			expectedCA:    "root",
		},
		"root-then-intermediate": {
			leaf:          leaf,
			trustChain:    []*testCert{root, intermediate},
			expectedChain: []string{"leaf", "intermediate"},
			expectedCA:    "root",
		},
		"multiple-intermediates-out-of-order": {
			leaf:          leaf2,
			trustChain:    []*testCert{root, intermediate1, intermediate2},
			expectedChain: []string{"leaf2", "intermediate2", "intermediate1"},
			expectedCA:    "root",
		},
		"no-root-uses-topmost-intermediate": {
			leaf:          leaf2,
			trustChain:    []*testCert{intermediate1, intermediate2},
			expectedChain: []string{"leaf2", "intermediate2", "intermediate1"},
			expectedCA:    "intermediate1",
		},
		"leaf-signed-directly-by-root": {
			leaf:          newTestCert(t, "leaf-from-root", false, root),
			trustChain:    []*testCert{root},
			expectedChain: []string{"leaf-from-root"},
			expectedCA:    "root",
		},
		"unrelated-certificates-are-ignored": {
			leaf:          leaf,
			trustChain:    []*testCert{otherIntermediate, intermediate, otherRoot, root},
			expectedChain: []string{"leaf", "intermediate"},
			expectedCA:    "root",
		},
		"empty-trust-chain": {
			leaf:          leaf,
			trustChain:    nil,
			expectedChain: []string{"leaf"},
		},
		"trust-chain-does-not-match-leaf": {
			leaf:          leaf,
			trustChain:    []*testCert{otherIntermediate, otherRoot},
			expectedError: errChainDoesNotMatchLeaf,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			chain, ca, err := buildChain(tc.leaf.cert, certs(tc.trustChain...))
			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedChain, subjects(chain), "unexpected tls.crt chain")
			if tc.expectedCA == "" {
				assert.Nil(t, ca, "unexpected ca.crt")
			} else if assert.NotNil(t, ca, "missing ca.crt") {
				assert.Equal(t, tc.expectedCA, ca.Subject.CommonName, "unexpected ca.crt")
			}
		})
	}
}

func TestEncodePEM(t *testing.T) {
	root := newTestCert(t, "root", true, nil)
	intermediate := newTestCert(t, "intermediate", true, root)
	leaf := newTestCert(t, "leaf", false, intermediate)

	rest := encodePEM(leaf.cert, intermediate.cert)
	var decoded []string
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		assert.Equal(t, "CERTIFICATE", block.Type)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		decoded = append(decoded, cert.Subject.CommonName)
	}
	assert.Equal(t, []string{"leaf", "intermediate"}, decoded)
	assert.Empty(t, rest)
}
