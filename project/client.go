package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

func createTrustStore(certPath string) (*x509.CertPool, error) {
	trustStore := x509.NewCertPool()
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	if !trustStore.AppendCertsFromPEM(certBytes) {
		return nil, fmt.Errorf("failed to append certificate")
	}
	return trustStore, nil
}

func showConnectionDetails(state tls.ConnectionState) {
	fmt.Printf("TLS Version: %s\n", describeTLSVersion(state.Version))
	fmt.Printf("Encryption Suite: %s\n", describeEncryptionSuite(state.CipherSuite))
	if len(state.PeerCertificates) > 0 {
		issuer := state.PeerCertificates[0].Issuer
		fmt.Printf("Issuer Organization: %s\n", issuer.Organization)
	}
}

func describeTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "Unknown"
	}
}

func describeEncryptionSuite(encryptionSuite uint16) string {
	switch encryptionSuite {
	case tls.TLS_AES_128_GCM_SHA256:
		return "AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "RSA_WITH_AES_256_GCM_SHA384"
	default:
		return "Unknown"
	}
}

func checkServerAvailability(url string, timeout time.Duration, httpClient *http.Client) bool {
	endTime := time.Now().Add(timeout)
	for time.Now().Before(endTime) {
		response, err := httpClient.Get(url)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		if response != nil && response.StatusCode == http.StatusOK {
			response.Body.Close()
			return true
		}
	}
	return false
}

func main() {
	trustStore, err := createTrustStore("./certificate/cert.pem")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: trustStore,
			},
		},
	}

	if !checkServerAvailability("https://localhost:9090", 5*time.Second, httpClient) {
		fmt.Println("Server not found")
		return
	}

	var userSelection int
	for {
		fmt.Println("Main Menu")
		fmt.Println("1. Get message")
		fmt.Println("2. Send file")
		fmt.Println("3. Print connection details")
		fmt.Println("4. Quit")
		fmt.Print(">> ")

		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		userSelection = 0
		fmt.Sscanf(input, "%d", &userSelection)

		if userSelection == 1 {
			fetchMessage(httpClient)
		} else if userSelection == 2 {
			uploadFile(httpClient)
		} else if userSelection == 3 {
			displayConnectionDetails(httpClient)
		} else if userSelection == 
