package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type CA struct {
	Cert    *x509.Certificate
	Key     crypto.Signer
	CertPEM []byte
	KeyPEM  []byte
}

// NewCA generates a self-signed root CA with the given key algorithm.
// keyAlgo must be "ecdsa-p256" or "rsa-4096".
func NewCA(keyAlgo string) (*CA, error) {
	key, err := generateKey(keyAlgo)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "mtls-sandbox-ca",
			Organization: []string{"mTLS Sandbox"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := marshalPrivateKey(key)
	if err != nil {
		return nil, err
	}

	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// LoadCA reads an existing CA certificate and key from PEM files.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA key: %w", err)
	}

	return LoadCAFromPEM(certPEM, keyPEM)
}

// LoadCAFromPEM creates a CA from PEM-encoded certificate and key bytes.
func LoadCAFromPEM(certPEM, keyPEM []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA key: %w", err)
	}

	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// IssueCert creates a certificate signed by the CA.
// role must be "server" or "client", which controls ExtKeyUsage.
func (ca *CA) IssueCert(role, cn string, hostnames []string) (certPEM, keyPEM []byte, err error) {
	key, err := generateKey("ecdsa-p256")
	if err != nil {
		return nil, nil, fmt.Errorf("generating %s key: %w", role, err)
	}

	serial, err := serialNumber()
	if err != nil {
		return nil, nil, err
	}

	dnsNames, ips := parseSANs(hostnames)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"mTLS Sandbox"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		DNSNames:  dnsNames,
		IPAddresses: ips,
	}

	switch role {
	case "server":
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return nil, nil, fmt.Errorf("role must be server or client; got %q", role)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating %s certificate: %w", role, err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err = marshalPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, keyPEM, nil
}

// Persist writes all certificate and key PEM files to the given directory.
func Persist(dir string, caCert, caKey, serverCert, serverKey, clientCert, clientKey []byte) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating cert directory: %w", err)
	}

	files := map[string][]byte{
		"ca.crt":     caCert,
		"ca.key":     caKey,
		"server.crt": serverCert,
		"server.key": serverKey,
		"client.crt": clientCert,
		"client.key": clientKey,
	}

	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
	}

	return nil
}

// PrintBundle writes a human-readable summary of the certificate bundle to w.
func PrintBundle(w io.Writer, caCert, serverCert, clientCert []byte) {
	fmt.Fprintln(w, "=== mTLS Sandbox Certificate Bundle ===")
	fmt.Fprintln(w)

	printCertInfo(w, "CA Certificate", caCert)
	printCertInfo(w, "Server Certificate", serverCert)
	printCertInfo(w, "Client Certificate", clientCert)

	fmt.Fprintln(w, "=== Client PEM (copy for your TLS config) ===")
	fmt.Fprintln(w)
	fmt.Fprint(w, string(clientCert))
	fmt.Fprintln(w)
}

func printCertInfo(w io.Writer, label string, certPEM []byte) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		fmt.Fprintf(w, "[%s] failed to decode PEM\n", label)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Fprintf(w, "[%s] failed to parse: %v\n", label, err)
		return
	}

	fmt.Fprintf(w, "[%s]\n", label)
	fmt.Fprintf(w, "  Subject:    %s\n", cert.Subject.CommonName)
	fmt.Fprintf(w, "  Issuer:     %s\n", cert.Issuer.CommonName)
	fmt.Fprintf(w, "  Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Fprintf(w, "  Not After:  %s\n", cert.NotAfter.Format(time.RFC3339))
	if len(cert.DNSNames) > 0 {
		fmt.Fprintf(w, "  DNS SANs:   %v\n", cert.DNSNames)
	}
	if len(cert.IPAddresses) > 0 {
		fmt.Fprintf(w, "  IP SANs:    %v\n", cert.IPAddresses)
	}
	fmt.Fprintln(w)
}

func generateKey(algo string) (crypto.Signer, error) {
	switch algo {
	case "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s (use ecdsa-p256 or rsa-4096)", algo)
	}
}

func marshalPrivateKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		// Try PKCS1 and EC formats as fallback.
		if k, err2 := x509.ParsePKCS1PrivateKey(der); err2 == nil {
			return k, nil
		}
		if k, err2 := x509.ParseECPrivateKey(der); err2 == nil {
			return k, nil
		}
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}
	return signer, nil
}

func serialNumber() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	return n, nil
}

func parseSANs(hostnames []string) (dnsNames []string, ips []net.IP) {
	for _, h := range hostnames {
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}
	return
}
