//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Portions derived from Younes Douici's ssh3-uid-helper project.
// See README.md for dependency and attribution details.
//
// CMXsafe SSH3 privilege-separation client.
//
// Derived from Younes Douici's ssh3-uid-helper client and redistributed under
// Apache-2.0 with permission from the rights holder.  The daemon remains a
// separate, versioned runtime dependency; this file is its SSH3-side client.
//
// The authenticated Unix UID is the only identity supplied to the daemon. The
// daemon derives the canonical username, primary GID and source IPv6 itself.
package cmd

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	helperMagic          = uint32(0x434d5848) // CMXH
	helperVersion        = uint16(2)
	helperRequestSize    = 40
	helperReplySize      = 24
	helperTimeout        = 6 * time.Second
	helperMinServicePort = 1024

	helperOpTCP       = uint16(1)
	helperOpUDP       = uint16(2)
	helperOpListenTCP = uint16(3)
	helperOpBindUDP   = uint16(4)
	helperOpAcceptTCP = uint16(5)
)

var (
	helperSocketPath  = "/run/ssh3-helper/helper.sock"
	helperExpectedUID = uint32(0)
)

type helperStatus uint16

const (
	helperOK                 helperStatus = 0
	helperMalformed          helperStatus = 1
	helperUnauthorized       helperStatus = 2
	helperInvalidIdentity    helperStatus = 3
	helperInvalidDestination helperStatus = 4
	helperSocketFailed       helperStatus = 5
	helperBusy               helperStatus = 6
	helperInternal           helperStatus = 7
	helperInvalidSocket      helperStatus = 8
)

func (status helperStatus) String() string {
	switch status {
	case helperMalformed:
		return "malformed request"
	case helperUnauthorized:
		return "unauthorized caller"
	case helperInvalidIdentity:
		return "invalid CMXsafe identity"
	case helperInvalidDestination:
		return "invalid destination"
	case helperSocketFailed:
		return "socket operation failed"
	case helperBusy:
		return "helper busy"
	case helperInternal:
		return "helper internal error"
	case helperInvalidSocket:
		return "invalid identity listener"
	default:
		return fmt.Sprintf("unknown status %d", status)
	}
}

func canonicalIPv6ForUID(uid uint32) (net.IP, error) {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, fmt.Errorf("lookup authenticated uid %d: %w", uid, err)
	}
	if len(account.Username) != 32 {
		return nil, fmt.Errorf("uid %d username is not a 32-hex CMXsafe identity", uid)
	}
	for _, char := range account.Username {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return nil, fmt.Errorf("uid %d username is not canonical lowercase hexadecimal", uid)
		}
	}
	text := make([]byte, 0, 39)
	for offset := 0; offset < len(account.Username); offset += 4 {
		if offset != 0 {
			text = append(text, ':')
		}
		text = append(text, account.Username[offset:offset+4]...)
	}
	ip := net.ParseIP(string(text))
	if ip == nil || ip.To4() != nil || ip.To16() == nil {
		return nil, fmt.Errorf("uid %d username does not encode IPv6", uid)
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return nil, fmt.Errorf("uid %d username encodes a reserved IPv6 identity", uid)
	}
	return ip.To16(), nil
}

func randomRequestID() (uint64, error) {
	var bytes [8]byte
	if _, err := io.ReadFull(rand.Reader, bytes[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(bytes[:]), nil
}

func buildHelperRequest(uid uint32, network string, sourcePort uint16, destination *net.UDPAddr) ([]byte, uint64, int, error) {
	if sourcePort < helperMinServicePort {
		return nil, 0, 0, fmt.Errorf("identity source port must be between %d and 65535", helperMinServicePort)
	}
	if destination == nil || destination.Port < 1 || destination.Port > 65535 || destination.Zone != "" {
		return nil, 0, 0, errors.New("destination must be an unscoped IPv6 address with a valid port")
	}
	ip := destination.IP.To16()
	if ip == nil || destination.IP.To4() != nil {
		return nil, 0, 0, errors.New("CMXsafe helper accepts IPv6 destinations only")
	}
	if destination.IP.IsUnspecified() || destination.IP.IsLoopback() ||
		destination.IP.IsMulticast() || destination.IP.IsLinkLocalUnicast() {
		return nil, 0, 0, errors.New("CMXsafe helper rejects reserved IPv6 destinations")
	}
	var operation uint16
	var socketType int
	switch network {
	case "tcp6":
		operation = helperOpTCP
		socketType = unix.SOCK_STREAM
	case "udp6":
		operation = helperOpUDP
		socketType = unix.SOCK_DGRAM
	default:
		return nil, 0, 0, fmt.Errorf("unsupported helper network %q", network)
	}
	requestID, err := randomRequestID()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("generate request id: %w", err)
	}
	request := make([]byte, helperRequestSize)
	binary.BigEndian.PutUint32(request[0:4], helperMagic)
	binary.BigEndian.PutUint16(request[4:6], helperVersion)
	binary.BigEndian.PutUint16(request[6:8], operation)
	binary.BigEndian.PutUint64(request[8:16], requestID)
	binary.BigEndian.PutUint32(request[16:20], uid)
	binary.BigEndian.PutUint16(request[20:22], uint16(destination.Port))
	// Protocol v2 assigns the former reserved field to the client-observed
	// source port.  The daemon still derives the source IPv6 solely from UID.
	binary.BigEndian.PutUint16(request[22:24], sourcePort)
	copy(request[24:40], ip)
	return request, requestID, socketType, nil
}

func buildHelperServiceRequest(uid uint32, network string, port int) ([]byte, uint64, int, error) {
	if port < helperMinServicePort || port > 65535 {
		return nil, 0, 0, fmt.Errorf("service port must be between %d and 65535", helperMinServicePort)
	}
	var operation uint16
	var socketType int
	switch network {
	case "tcp6":
		operation = helperOpListenTCP
		socketType = unix.SOCK_STREAM
	case "udp6":
		operation = helperOpBindUDP
		socketType = unix.SOCK_DGRAM
	default:
		return nil, 0, 0, fmt.Errorf("unsupported helper service network %q", network)
	}
	requestID, err := randomRequestID()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("generate request id: %w", err)
	}
	request := make([]byte, helperRequestSize)
	binary.BigEndian.PutUint32(request[0:4], helperMagic)
	binary.BigEndian.PutUint16(request[4:6], helperVersion)
	binary.BigEndian.PutUint16(request[6:8], operation)
	binary.BigEndian.PutUint64(request[8:16], requestID)
	binary.BigEndian.PutUint32(request[16:20], uid)
	binary.BigEndian.PutUint16(request[20:22], uint16(port))
	// Bytes 24:40 remain zero: the daemon derives the bind address from UID.
	return request, requestID, socketType, nil
}

func buildHelperAcceptRequest(uid uint32, port int) ([]byte, uint64, error) {
	request, requestID, _, err := buildHelperServiceRequest(uid, "tcp6", port)
	if err != nil {
		return nil, 0, err
	}
	binary.BigEndian.PutUint16(request[6:8], helperOpAcceptTCP)
	return request, requestID, nil
}

func validateHelperPeer(connection *net.UnixConn) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return fmt.Errorf("helper SyscallConn: %w", err)
	}
	var peer *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("inspect helper peer: %w", err)
	}
	if peerErr != nil {
		return fmt.Errorf("inspect helper credentials: %w", peerErr)
	}
	if peer == nil || peer.Uid != helperExpectedUID {
		return fmt.Errorf("helper peer uid is not trusted: got %v, want %d", peer, helperExpectedUID)
	}
	return nil
}

func receiveHelperReply(connection *net.UnixConn) ([]byte, []byte, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, nil, fmt.Errorf("helper SyscallConn: %w", err)
	}
	payload := make([]byte, helperReplySize)
	control := make([]byte, unix.CmsgSpace(4))
	var payloadLength int
	var controlLength int
	var flags int
	var receiveErr error
	if err := raw.Read(func(fd uintptr) bool {
		payloadLength, controlLength, flags, _, receiveErr = unix.Recvmsg(
			int(fd), payload, control, unix.MSG_CMSG_CLOEXEC)
		if receiveErr == unix.EAGAIN || receiveErr == unix.EWOULDBLOCK {
			receiveErr = nil
			return false
		}
		return true
	}); err != nil {
		return nil, nil, fmt.Errorf("wait for helper reply: %w", err)
	}
	if receiveErr != nil {
		return nil, nil, fmt.Errorf("receive helper reply: %w", receiveErr)
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || payloadLength != helperReplySize {
		return nil, nil, errors.New("truncated or oversized helper reply")
	}
	return payload[:payloadLength], control[:controlLength], nil
}

func parseReceivedFD(control []byte) (int, error) {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return -1, fmt.Errorf("parse helper ancillary data: %w", err)
	}
	var allFDs []int
	for _, message := range messages {
		fds, rightsErr := unix.ParseUnixRights(&message)
		if rightsErr != nil {
			for _, fd := range allFDs {
				unix.Close(fd)
			}
			return -1, fmt.Errorf("parse SCM_RIGHTS: %w", rightsErr)
		}
		allFDs = append(allFDs, fds...)
	}
	if len(allFDs) != 1 {
		for _, fd := range allFDs {
			unix.Close(fd)
		}
		return -1, fmt.Errorf("helper returned %d descriptors, expected exactly one", len(allFDs))
	}
	return allFDs[0], nil
}

func closeReceivedRights(control []byte) {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return
	}
	for _, message := range messages {
		fds, rightsErr := unix.ParseUnixRights(&message)
		if rightsErr != nil {
			continue
		}
		for _, fd := range fds {
			unix.Close(fd)
		}
	}
}

func verifyReceivedFDUID(fd int, uid uint32) error {
	var state unix.Stat_t
	if err := unix.Fstat(fd, &state); err != nil {
		return fmt.Errorf("inspect helper descriptor owner: %w", err)
	}
	if state.Uid != uid {
		return fmt.Errorf("helper descriptor uid mismatch: got %d, want %d", state.Uid, uid)
	}
	return nil
}

func verifyIdentityConnection(connection net.Conn, source net.IP, sourcePort uint16, destination *net.UDPAddr, socketType int) error {
	var localIP net.IP
	var localPort int
	var remoteIP net.IP
	var remotePort int
	switch typed := connection.(type) {
	case *net.TCPConn:
		if socketType != unix.SOCK_STREAM {
			return errors.New("helper returned TCP for a non-TCP request")
		}
		localIP = typed.LocalAddr().(*net.TCPAddr).IP
		localPort = typed.LocalAddr().(*net.TCPAddr).Port
		remote := typed.RemoteAddr().(*net.TCPAddr)
		remoteIP, remotePort = remote.IP, remote.Port
	case *net.UDPConn:
		if socketType != unix.SOCK_DGRAM {
			return errors.New("helper returned UDP for a non-UDP request")
		}
		localIP = typed.LocalAddr().(*net.UDPAddr).IP
		localPort = typed.LocalAddr().(*net.UDPAddr).Port
		remote := typed.RemoteAddr().(*net.UDPAddr)
		remoteIP, remotePort = remote.IP, remote.Port
	default:
		return fmt.Errorf("helper returned unexpected connection type %T", connection)
	}
	if !localIP.Equal(source) || localPort != int(sourcePort) {
		return fmt.Errorf("helper socket source mismatch: got [%s]:%d, want [%s]:%d", localIP, localPort, source, sourcePort)
	}
	if !remoteIP.Equal(destination.IP) || remotePort != destination.Port {
		return fmt.Errorf("helper socket destination mismatch: got [%s]:%d, want [%s]:%d",
			remoteIP, remotePort, destination.IP, destination.Port)
	}
	return nil
}

func sendHelperRequest(connection *net.UnixConn, request []byte, passedFD int) error {
	if passedFD < 0 {
		written, err := connection.Write(request)
		if err != nil {
			return err
		}
		if written != len(request) {
			return io.ErrShortWrite
		}
		return nil
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	if err := raw.Write(func(fd uintptr) bool {
		var written int
		written, sendErr = unix.SendmsgN(int(fd), request, unix.UnixRights(passedFD), nil, unix.MSG_NOSIGNAL)
		if sendErr == unix.EAGAIN || sendErr == unix.EWOULDBLOCK {
			sendErr = nil
			return false
		}
		if sendErr == nil && written != len(request) {
			sendErr = io.ErrShortWrite
		}
		return true
	}); err != nil {
		return err
	}
	return sendErr
}

func exchangeHelperRequest(request []byte, requestID uint64, passedFD int) (int, error) {
	connection, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: helperSocketPath, Net: "unixpacket"})
	if err != nil {
		return -1, fmt.Errorf("connect to CMXsafe helper: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(helperTimeout)); err != nil {
		return -1, fmt.Errorf("set helper deadline: %w", err)
	}
	if err := validateHelperPeer(connection); err != nil {
		return -1, err
	}
	if err := sendHelperRequest(connection, request, passedFD); err != nil {
		return -1, fmt.Errorf("send helper request: %w", err)
	}
	payload, control, err := receiveHelperReply(connection)
	if err != nil {
		return -1, err
	}
	if binary.BigEndian.Uint32(payload[0:4]) != helperMagic ||
		binary.BigEndian.Uint16(payload[4:6]) != helperVersion {
		closeReceivedRights(control)
		return -1, errors.New("invalid helper response header")
	}
	status := helperStatus(binary.BigEndian.Uint16(payload[6:8]))
	replyID := binary.BigEndian.Uint64(payload[8:16])
	if replyID != requestID && !(replyID == 0 && status != helperOK) {
		closeReceivedRights(control)
		return -1, errors.New("helper response request id mismatch")
	}
	systemErrno := syscall.Errno(binary.BigEndian.Uint32(payload[16:20]))
	if status != helperOK {
		closeReceivedRights(control)
		return -1, fmt.Errorf("helper rejected request: %s: %w", status, systemErrno)
	}
	receivedFD, err := parseReceivedFD(control)
	if err != nil {
		return -1, err
	}
	return receivedFD, nil
}

// dialIdentitySocket obtains a connected IPv6 TCP or UDP socket whose source
// address and Unix ownership are derived from the authenticated UID.
func dialIdentitySocket(uid uint32, network string, sourcePort uint16, destination *net.UDPAddr) (net.Conn, error) {
	source, err := canonicalIPv6ForUID(uid)
	if err != nil {
		return nil, err
	}
	request, requestID, socketType, err := buildHelperRequest(uid, network, sourcePort, destination)
	if err != nil {
		return nil, err
	}
	receivedFD, err := exchangeHelperRequest(request, requestID, -1)
	if err != nil {
		return nil, err
	}
	if err := verifyReceivedFDUID(receivedFD, uid); err != nil {
		unix.Close(receivedFD)
		return nil, err
	}
	file := os.NewFile(uintptr(receivedFD), "cmxsafe-identity-socket")
	if file == nil {
		unix.Close(receivedFD)
		return nil, errors.New("wrap helper descriptor")
	}
	defer file.Close()
	identityConnection, err := net.FileConn(file)
	if err != nil {
		return nil, fmt.Errorf("convert helper descriptor: %w", err)
	}
	if err := verifyIdentityConnection(identityConnection, source, sourcePort, destination, socketType); err != nil {
		identityConnection.Close()
		return nil, err
	}
	return identityConnection, nil
}

type identityTCPListener struct {
	uid      uint32
	port     int
	source   net.IP
	listener *net.TCPListener
}

func (listener *identityTCPListener) Accept() (net.Conn, error) {
	return listener.AcceptTCP()
}

func (listener *identityTCPListener) AcceptTCP() (*net.TCPConn, error) {
	for {
		listenerFile, err := listener.listener.File()
		if err != nil {
			return nil, fmt.Errorf("duplicate identity listener: %w", err)
		}
		descriptors := []unix.PollFd{{Fd: int32(listenerFile.Fd()), Events: unix.POLLIN}}
		ready, pollErr := unix.Poll(descriptors, 1000)
		if pollErr == unix.EINTR || ready == 0 {
			listenerFile.Close()
			continue
		}
		if pollErr != nil {
			listenerFile.Close()
			return nil, fmt.Errorf("wait for identity listener: %w", pollErr)
		}
		if descriptors[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			listenerFile.Close()
			return nil, errors.New("identity listener became unavailable")
		}
		request, requestID, err := buildHelperAcceptRequest(listener.uid, listener.port)
		if err != nil {
			listenerFile.Close()
			return nil, err
		}
		receivedFD, exchangeErr := exchangeHelperRequest(request, requestID, int(listenerFile.Fd()))
		listenerFile.Close()
		if exchangeErr != nil {
			if errors.Is(exchangeErr, syscall.ETIMEDOUT) || errors.Is(exchangeErr, syscall.EAGAIN) ||
				errors.Is(exchangeErr, syscall.EINTR) {
				continue
			}
			return nil, exchangeErr
		}
		if err := verifyReceivedFDUID(receivedFD, listener.uid); err != nil {
			unix.Close(receivedFD)
			return nil, err
		}
		file := os.NewFile(uintptr(receivedFD), "cmxsafe-identity-accepted-tcp")
		if file == nil {
			unix.Close(receivedFD)
			return nil, errors.New("wrap helper accepted descriptor")
		}
		connection, err := net.FileConn(file)
		file.Close()
		if err != nil {
			return nil, fmt.Errorf("convert helper accepted descriptor: %w", err)
		}
		tcp, ok := connection.(*net.TCPConn)
		if !ok {
			connection.Close()
			return nil, fmt.Errorf("helper returned %T for accepted TCP", connection)
		}
		local := tcp.LocalAddr().(*net.TCPAddr)
		remote := tcp.RemoteAddr().(*net.TCPAddr)
		if !local.IP.Equal(listener.source) || local.Port != listener.port ||
			remote.IP.To16() == nil || remote.IP.To4() != nil {
			tcp.Close()
			return nil, fmt.Errorf("helper accepted socket endpoints are invalid: local=%s remote=%s", local, remote)
		}
		return tcp, nil
	}
}

func (listener *identityTCPListener) Close() error {
	return listener.listener.Close()
}

func (listener *identityTCPListener) Addr() net.Addr {
	return listener.listener.Addr()
}

func (listener *identityTCPListener) SyscallConn() (syscall.RawConn, error) {
	return listener.listener.SyscallConn()
}

func listenIdentityTCP(uid uint32, requested *net.TCPAddr) (*identityTCPListener, error) {
	if requested == nil || requested.Zone != "" {
		return nil, errors.New("TCP service bind must be an unscoped canonical IPv6 address")
	}
	source, err := canonicalIPv6ForUID(uid)
	if err != nil {
		return nil, err
	}
	if !requested.IP.Equal(source) {
		return nil, fmt.Errorf("TCP service bind address %s does not match authenticated identity %s", requested.IP, source)
	}
	port := requested.Port
	request, requestID, _, err := buildHelperServiceRequest(uid, "tcp6", port)
	if err != nil {
		return nil, err
	}
	receivedFD, err := exchangeHelperRequest(request, requestID, -1)
	if err != nil {
		return nil, err
	}
	if err := verifyReceivedFDUID(receivedFD, uid); err != nil {
		unix.Close(receivedFD)
		return nil, err
	}
	file := os.NewFile(uintptr(receivedFD), "cmxsafe-identity-tcp-listener")
	if file == nil {
		unix.Close(receivedFD)
		return nil, errors.New("wrap helper listener descriptor")
	}
	defer file.Close()
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, fmt.Errorf("convert helper listener descriptor: %w", err)
	}
	tcp, ok := listener.(*net.TCPListener)
	if !ok {
		listener.Close()
		return nil, fmt.Errorf("helper returned %T for TCP listener", listener)
	}
	local := tcp.Addr().(*net.TCPAddr)
	if !local.IP.Equal(source) || local.Port != port {
		tcp.Close()
		return nil, fmt.Errorf("helper listener mismatch: got %s, want [%s]:%d", local, source, port)
	}
	return &identityTCPListener{uid: uid, port: port, source: source, listener: tcp}, nil
}

func bindIdentityUDP(uid uint32, requested *net.UDPAddr) (*net.UDPConn, error) {
	if requested == nil || requested.Zone != "" {
		return nil, errors.New("UDP service bind must be an unscoped canonical IPv6 address")
	}
	source, err := canonicalIPv6ForUID(uid)
	if err != nil {
		return nil, err
	}
	if !requested.IP.Equal(source) {
		return nil, fmt.Errorf("UDP service bind address %s does not match authenticated identity %s", requested.IP, source)
	}
	port := requested.Port
	request, requestID, _, err := buildHelperServiceRequest(uid, "udp6", port)
	if err != nil {
		return nil, err
	}
	receivedFD, err := exchangeHelperRequest(request, requestID, -1)
	if err != nil {
		return nil, err
	}
	if err := verifyReceivedFDUID(receivedFD, uid); err != nil {
		unix.Close(receivedFD)
		return nil, err
	}
	file := os.NewFile(uintptr(receivedFD), "cmxsafe-identity-udp-service")
	if file == nil {
		unix.Close(receivedFD)
		return nil, errors.New("wrap helper UDP descriptor")
	}
	defer file.Close()
	packet, err := net.FilePacketConn(file)
	if err != nil {
		return nil, fmt.Errorf("convert helper UDP descriptor: %w", err)
	}
	udp, ok := packet.(*net.UDPConn)
	if !ok {
		packet.Close()
		return nil, fmt.Errorf("helper returned %T for UDP service", packet)
	}
	local := udp.LocalAddr().(*net.UDPAddr)
	if !local.IP.Equal(source) || local.Port != port {
		udp.Close()
		return nil, fmt.Errorf("helper UDP bind mismatch: got %s, want [%s]:%d", local, source, port)
	}
	return udp, nil
}

func dialIdentityTCP(uid uint32, sourcePort uint16, destination *net.TCPAddr) (*net.TCPConn, error) {
	if destination == nil {
		return nil, errors.New("nil TCP destination")
	}
	connection, err := dialIdentitySocket(uid, "tcp6", sourcePort, &net.UDPAddr{
		IP: destination.IP, Port: destination.Port, Zone: destination.Zone,
	})
	if err != nil {
		return nil, err
	}
	tcp, ok := connection.(*net.TCPConn)
	if !ok {
		connection.Close()
		return nil, fmt.Errorf("helper returned %T for TCP", connection)
	}
	return tcp, nil
}

func dialIdentityUDP(uid uint32, sourcePort uint16, destination *net.UDPAddr) (*net.UDPConn, error) {
	connection, err := dialIdentitySocket(uid, "udp6", sourcePort, destination)
	if err != nil {
		return nil, err
	}
	udp, ok := connection.(*net.UDPConn)
	if !ok {
		connection.Close()
		return nil, fmt.Errorf("helper returned %T for UDP", connection)
	}
	return udp, nil
}
