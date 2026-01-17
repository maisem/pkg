// Copyright (c) 2025 AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshttp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	gssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
	"tailscale.com/util/set"
)

// testHandler returns a simple HTTP response for testing
func testHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]string{
			"message": "Hello from SSH tunnel!",
			"method":  r.Method,
			"path":    r.URL.Path,
		}
		json.NewEncoder(w).Encode(response)
	})
}

// generateSSHKeyPair generates an ED25519 key pair and returns the private key and public key
func generateSSHKeyPair() (ssh.Signer, ssh.PublicKey, error) {
	// Generate ED25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %v", err)
	}

	// Marshal private key to PKCS8 format
	privateBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	// Encode private key to PEM format
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateBytes,
	})

	// Parse private key for SSH
	privateKey, err := ssh.ParsePrivateKey(privatePEM)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Create SSH public key from ED25519 public key
	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SSH public key: %v", err)
	}

	return privateKey, sshPubKey, nil
}

func TestSSHPortForward(t *testing.T) {
	// Generate SSH key pairs
	hostSigner, _, err := generateSSHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate host key: %v", err)
	}

	clientSigner, clientPubKey, err := generateSSHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	// Create test HTTP handler
	handler := testHandler()

	// Create in-memory connection pair
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	// Start SSH server in a goroutine
	go func() {
		serverConn, err := ln.Accept()
		ln.Close()
		if err != nil {
			t.Errorf("Failed to accept: %v", err)
			return
		}
		defer serverConn.Close()
		// Create SSH server
		sshServer := &Server{
			Name:           "test-sshttp",
			Handler:        handler,
			HostSigners:    []gssh.Signer{hostSigner},
			AuthorizedKeys: set.Of(string(clientPubKey.Marshal())),
		}
		sshServer.HandleConn(serverConn)
	}()

	sshDialer := &Dialer{
		SSHAddr: ln.Addr().String(),
		Config: &ssh.ClientConfig{
			User: "testuser",
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(clientSigner),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		},
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: sshDialer.DialContext,
		},
	}

	// Make HTTP request through the SSH tunnel
	resp, err := httpClient.Get("http://127.0.0.1:8080/test")
	if err != nil {
		t.Fatalf("Failed to make HTTP request through SSH tunnel: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Read and verify response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var response map[string]string
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Verify response content
	expectedMessage := "Hello from SSH tunnel!"
	if response["message"] != expectedMessage {
		t.Errorf("Expected message %q, got %q", expectedMessage, response["message"])
	}

	if response["method"] != "GET" {
		t.Errorf("Expected method GET, got %s", response["method"])
	}

	if response["path"] != "/test" {
		t.Errorf("Expected path /test, got %s", response["path"])
	}

	t.Logf("Successfully made HTTP request through SSH tunnel: %s", string(body))
}
