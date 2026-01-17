// Copyright (c) 2025 AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sshttp provides HTTP-over-SSH functionality, allowing HTTP requests
// to be tunneled through SSH connections using a custom "sshttp" channel type.
//
// This package is useful for scenarios where you need to proxy HTTP traffic
// through SSH connections, such as accessing internal services through
// secure tunnels or implementing HTTP APIs over SSH.
//
// The package provides two main components:
//   - Server: Accepts custom "sshttp" channels and forwards them to an HTTP handler
//   - Dialer: Provides a dialer function that tunnels connections through SSH
//
// Example server usage:
//
//	// Create an HTTP handler
//	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		fmt.Fprintf(w, "Hello from SSH tunnel!")
//	})
//
//	// Create the HTTP-over-SSH server
//	server := &sshttp.Server{
//		Name:           "my-server",
//		Handler:        handler,
//		HostSigners:    []gssh.Signer{hostSigner},
//		AuthorizedKeys: set.Of(string(clientPubKey.Marshal())),
//	}
//
//	// Listen for connections and serve
//	ln, _ := net.Listen("tcp", ":2222")
//	server.Serve(ln)
//
// Example client usage with Dialer:
//
//	// Create SSH client config with whatever is needed to connect
//	config := &ssh.ClientConfig{
//		// ... SSH client configuration
//	}
//
//	// Create dialer for tunneling through SSH
//	dialer := &sshttp.Dialer{
//		SSHAddr: "ssh-server:2222",
//		Config:  config,
//	}
//
//	// Create HTTP client using the SSH dialer
//	client := &http.Client{
//		Transport: &http.Transport{
//			DialContext: dialer.DialContext,
//		},
//	}
//
//	// Make HTTP request through SSH tunnel
//	resp, err := client.Get("http://ignored/api")
package sshttp

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	gssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
	"tailscale.com/net/netutil"
	"tailscale.com/util/set"
)

// channelConn is a net.Conn that wraps a ssh.Channel.
// It implements the net.Conn interface and can be used as a net.Conn.
type channelConn struct {
	ssh.Channel
	sshConn ssh.Conn
	// closeConn specifies whether to close the underlying ssh.Conn when
	// channelConn is closed. This is useful when the lifecycle of the ssh.Conn
	// is tied to the lifecycle of the channelConn.
	closeConn bool
}

// Close closes the connection.
// If closeConn is true, the underlying ssh.Conn will also be closed.
func (c channelConn) Close() error {
	var err1, err2 error
	if c.Channel != nil {
		err1 = c.Channel.Close()
	}
	if c.closeConn {
		err2 = c.sshConn.Close()
	}
	return errors.Join(err1, err2)
}

func (c channelConn) LocalAddr() net.Addr {
	return c.sshConn.LocalAddr()
}

func (c channelConn) RemoteAddr() net.Addr {
	return c.sshConn.RemoteAddr()
}

func (c channelConn) SetDeadline(t time.Time) error {
	return errors.New("chanAsConn: SetDeadline: unimplemented")
}

func (c channelConn) SetReadDeadline(t time.Time) error {
	return errors.New("chanAsConn: SetReadDeadline: unimplemented")
}

func (c channelConn) SetWriteDeadline(t time.Time) error {
	return errors.New("chanAsConn: SetWriteDeadline: unimplemented")
}

var _ net.Conn = channelConn{}

// Server provides HTTP-over-SSH functionality by accepting custom "sshttp" channels
// and forwarding them to an HTTP handler. The server handles SSH authentication
// via public keys and manages the SSH server lifecycle.
type Server struct {
	// Name is the name of the server to use for the SSH server.
	// If empty, "sshttp" will be used.
	Name string
	// HostSigners are the host signers to use for the SSH server.
	// It must be provided.
	HostSigners []gssh.Signer
	// AuthorizedKeys are the authorized keys to use for the SSH server.
	// It must be provided.
	AuthorizedKeys set.Set[string]
	// Handler is the HTTP handler to use for the SSH server.
	// It must be provided.
	Handler http.Handler
}

func (s *Server) Serve(ln net.Listener) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.HandleConn(conn)
	}
}

func (s *Server) HandleConn(conn net.Conn) {
	if len(s.HostSigners) == 0 {
		log.Printf("[sshttp]: no host signers provided, closing connection")
		conn.Close()
		return
	}
	if len(s.AuthorizedKeys) == 0 {
		log.Printf("[sshttp]: no authorized keys provided, closing connection")
		conn.Close()
		return
	}
	ss := &gssh.Server{
		Version:     cmp.Or(s.Name, "sshttp"),
		HostSigners: s.HostSigners,
		ChannelHandlers: map[string]gssh.ChannelHandler{
			"sshttp": s.Handle,
		},
		PublicKeyHandler: func(ctx gssh.Context, key gssh.PublicKey) bool {
			return s.AuthorizedKeys.Contains(string(key.Marshal()))
		},
	}
	defer ss.Close()
	ss.HandleConn(conn)
}

// Handle processes incoming "sshttp" channels and forwards them to the HTTP handler.
// It accepts the channel and serves HTTP requests over the SSH channel using the
// configured Handler.
func (s *Server) Handle(srv *gssh.Server, sshConn *ssh.ServerConn, newChan ssh.NewChannel, ctx gssh.Context) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)

	hs := &http.Server{Handler: s.Handler}
	chConn := channelConn{sshConn: sshConn, Channel: ch}
	ln := netutil.NewOneConnListener(chConn, nil)
	go hs.Serve(ln)
}

type Dialer struct {
	// SSHAddr is the address of the SSH server in the format "host:port".
	// The port must be provided.
	SSHAddr string
	// BaseDialer is the base dialer to use for the SSH connection.
	// If nil, a net.Dialer will be used.
	BaseDialer *net.Dialer

	// Config is the client config to use for the SSH connection.
	// It must be provided.
	Config *ssh.ClientConfig
}

func (d *Dialer) client(ctx context.Context, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	if _, _, err := net.SplitHostPort(d.SSHAddr); err != nil {
		return nil, fmt.Errorf("invalid SSH address: %w", err)
	}
	var dial func(ctx context.Context, network, addr string) (net.Conn, error)
	if d.BaseDialer != nil {
		dial = d.BaseDialer.DialContext
	} else {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "tcp", d.SSHAddr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func (d *Dialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
	// Create SSH client

	// Connect to SSH server
	client, err := d.client(ctx, d.SSHAddr, d.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to establish SSH connection: %w", err)
	}

	// Create a sshttp channel
	channel, reqs, err := client.OpenChannel("sshttp", nil)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to open sshttp channel: %w", err)
	}

	// Discard channel requests
	go ssh.DiscardRequests(reqs)

	return channelConn{sshConn: client, Channel: channel, closeConn: true}, nil
}
