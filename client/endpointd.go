// Copyright 2026 David de Hoz Diego
// SPDX-License-Identifier: Apache-2.0
//
// CMXsafe endpointd integration.  The line protocol is maintained by the
// CMXsafeMAC-IPv6 project; this client intentionally fails closed when the
// daemon is absent or rejects an address.
package client

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const defaultEndpointdSocket = "/run/cmxsafe/endpointd.sock"

type endpointdReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func endpointdSocketPath() string {
	if path := os.Getenv("CMXSAFE_ENDPOINTD_SOCK"); path != "" {
		return path
	}
	return defaultEndpointdSocket
}

func validateMirrorPeer(ip net.IP, port int) error {
	if port < 1024 || port > 65535 {
		return errors.New("mirror peer port must be in 1024..65535")
	}
	if ip == nil || ip.To4() != nil || ip.To16() == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return errors.New("mirror peer must be a non-reserved IPv6 address")
	}
	return nil
}

// ssh3Channel is kept tiny so endpointd protocol tests need no QUIC stream.
type ssh3Channel interface{ ChannelID() uint64 }

func endpointdPeer(op string, leaseID uint64, ip net.IP) error {
	if op != "ensure" && op != "release" {
		return fmt.Errorf("invalid endpointd operation %q", op)
	}
	if leaseID == 0 {
		return errors.New("endpointd lease id must be a non-zero channel id")
	}
	if err := validateMirrorPeer(ip, 1024); err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", endpointdSocketPath(), 2*time.Second)
	if err != nil {
		return fmt.Errorf("connect endpointd: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	// endpointd v1 binds this opaque per-channel lease ID to the caller identity
	// derived from SO_PEERCRED (PID plus process start marker).  No caller-
	// supplied process ownership token crosses this boundary.
	if _, err := fmt.Fprintf(conn, "v1\t%s\tpeer\t%d\t%s\n", op, leaseID, ip.To16().String()); err != nil {
		return fmt.Errorf("write endpointd request: %w", err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read endpointd response: %w", err)
	}
	var reply endpointdReply
	if err := json.Unmarshal(line, &reply); err != nil {
		return fmt.Errorf("decode endpointd response: %w", err)
	}
	if !reply.OK {
		if reply.Error == "" {
			reply.Error = "request rejected"
		}
		return fmt.Errorf("endpointd: %s", reply.Error)
	}
	return nil
}

func dialMirrorTCP(channel ssh3Channel, peer, target *net.TCPAddr) (*net.TCPConn, func(), error) {
	if peer == nil || peer.Zone != "" || target == nil {
		return nil, nil, errors.New("invalid TCP mirror tuple")
	}
	if err := validateMirrorPeer(peer.IP, peer.Port); err != nil {
		return nil, nil, err
	}
	leaseID := channel.ChannelID()
	if err := endpointdPeer("ensure", leaseID, peer.IP); err != nil {
		return nil, nil, err
	}
	release := func() { _ = endpointdPeer("release", leaseID, peer.IP) }
	conn, err := net.DialTCP("tcp6", peer, target)
	if err != nil {
		release()
		return nil, nil, fmt.Errorf("dial TCP mirror socket: %w", err)
	}
	return conn, release, nil
}

func dialMirrorUDP(channel ssh3Channel, peer, target *net.UDPAddr) (*net.UDPConn, func(), error) {
	if peer == nil || peer.Zone != "" || target == nil {
		return nil, nil, errors.New("invalid UDP mirror tuple")
	}
	if err := validateMirrorPeer(peer.IP, peer.Port); err != nil {
		return nil, nil, err
	}
	leaseID := channel.ChannelID()
	if err := endpointdPeer("ensure", leaseID, peer.IP); err != nil {
		return nil, nil, err
	}
	release := func() { _ = endpointdPeer("release", leaseID, peer.IP) }
	conn, err := net.DialUDP("udp6", peer, target)
	if err != nil {
		release()
		return nil, nil, fmt.Errorf("dial UDP mirror socket: %w", err)
	}
	return conn, release, nil
}
