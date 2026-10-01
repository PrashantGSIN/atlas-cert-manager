package signer

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var errChainDoesNotMatchLeaf = errors.New("atlas trust chain does not contain the issuer of the issued certificate")

// buildChain orders the certificates returned by the Atlas trust chain
// endpoint into a path starting at the leaf, following cert-manager's
// convention for issuers:
//
//   - chain is the leaf followed by its intermediates, in order, and is
//     written to tls.crt. The root is never included.
//   - ca is the root of the chain and is written to ca.crt. If the trust
//     chain does not include a root, the topmost intermediate is used.
//
// The order in which Atlas returns the trust chain is not relied upon.
func buildChain(leaf *x509.Certificate, trustChain []*x509.Certificate) (chain []*x509.Certificate, ca *x509.Certificate, err error) {
	chain = []*x509.Certificate{leaf}
	if len(trustChain) == 0 {
		return chain, nil, nil
	}

	used := make([]bool, len(trustChain))
	current := leaf
	for range trustChain {
		if isSelfSigned(current) {
			break
		}
		i := findIssuer(current, trustChain, used)
		if i < 0 {
			break
		}
		used[i] = true
		issuer := trustChain[i]
		if isSelfSigned(issuer) {
			return chain, issuer, nil
		}
		chain = append(chain, issuer)
		current = issuer
	}

	if len(chain) == 1 {
		return nil, nil, errChainDoesNotMatchLeaf
	}
	return chain, chain[len(chain)-1], nil
}

// findIssuer returns the index of the unused certificate in candidates that
// signed cert, or -1. A self-signed root is preferred over a cross-signed
// certificate with the same subject and key, so the path ends at the root.
func findIssuer(cert *x509.Certificate, candidates []*x509.Certificate, used []bool) int {
	found := -1
	for i, c := range candidates {
		if used[i] || !bytes.Equal(cert.RawIssuer, c.RawSubject) || cert.CheckSignatureFrom(c) != nil {
			continue
		}
		if isSelfSigned(c) {
			return i
		}
		if found < 0 {
			found = i
		}
	}
	return found
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil
}

// encodePEM concatenates certs as PEM CERTIFICATE blocks.
func encodePEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}
	return out
}
