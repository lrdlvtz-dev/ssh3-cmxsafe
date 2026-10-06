package ssh3

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/francoismichel/ssh3/util"
	"golang.org/x/exp/slices"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
)

const SSH_FRAME_TYPE = 0xaf3627e6

type ConversationID [32]byte

type conversationStream interface {
	io.ReadWriteCloser
	StreamID() quic.StreamID
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

func (cid ConversationID) String() string {
	return base64.StdEncoding.EncodeToString(cid[:])
}

type Conversation struct {
	controlStream             conversationStream
	maxPacketSize             uint64
	defaultDatagramsQueueSize uint64
	streamCreator             *quic.Conn
	messageSender             util.DatagramSender
	channelsManager           *channelsManager
	context                   context.Context
	cancelContext             context.CancelCauseFunc
	conversationID            ConversationID // generated using TLS exporters
	peerVersion               Version
	authorizationPolicy       AuthorizationPolicy

	channelsAcceptQueue *util.AcceptQueue[Channel]
}

func (c *Conversation) SetAuthorizationPolicy(policy AuthorizationPolicy) {
	c.authorizationPolicy = policy
}

func (c *Conversation) AuthorizationPolicy() AuthorizationPolicy {
	return c.authorizationPolicy
}

func GenerateConversationID(tls *tls.ConnectionState) (convID ConversationID, err error) {
	ret, err := tls.ExportKeyingMaterial("EXPORTER-SSH3", nil, 32)
	if err != nil {
		return convID, err
	}
	if len(ret) != len(convID) {
		return convID, fmt.Errorf("TLS returned a tls-exporter with the wrong length (%d instead of %d)", len(ret), len(convID))
	}
	copy(convID[:], ret)
	return convID, err
}

func NewClientConversation(maxPacketsize uint64, defaultDatagramsQueueSize uint64, tls *tls.ConnectionState) (*Conversation, error) {
	convID, err := GenerateConversationID(tls)
	if err != nil {
		log.Error().Msgf("could not generate conversation ID: %s", err)
		return nil, err
	}
	backgroundCtx, backgroundCancelCauseFunc := context.WithCancelCause(context.Background())
	conv := &Conversation{
		controlStream:             nil,
		channelsAcceptQueue:       util.NewAcceptQueue[Channel](),
		streamCreator:             nil,
		maxPacketSize:             maxPacketsize,
		defaultDatagramsQueueSize: defaultDatagramsQueueSize,
		channelsManager:           newChannelsManager(),
		context:                   backgroundCtx,
		cancelContext:             backgroundCancelCauseFunc,
		conversationID:            convID,

		// peerVersion set afterwards
	}
	return conv, nil
}

func (c *Conversation) handleIncomingChannel(stream *quic.Stream) error {
	controlStreamID, channelType, maxPacketSize, err := parseSSHChannelHeader(stream)
	if err != nil {
		return err
	}
	// todo: handle several conversations for the same client on the same connection ?
	// This can be done by defining the conversation ID as a combination between the control stream ID
	// and the tls exporter value, or computing the exporter value depending on the stream ID
	if controlStreamID != uint64(c.controlStream.StreamID()) {
		err := fmt.Errorf("wrong conversation control stream ID: %d instead of expected %d", controlStreamID, c.controlStream.StreamID())
		log.Error().Msgf("%s", err)
		return err
	}
	channelInfo := &ChannelInfo{
		ConversationID:       c.ConversationID(),
		ConversationStreamID: controlStreamID,
		ChannelID:            uint64(stream.StreamID()),
		ChannelType:          channelType,
		MaxPacketSize:        maxPacketSize,
	}

	newChannel := NewChannel(channelInfo.ConversationStreamID, channelInfo.ConversationID, uint64(stream.StreamID()), channelInfo.ChannelType, channelInfo.MaxPacketSize, &StreamByteReader{stream}, stream, nil, c.channelsManager, false, false, true, c.defaultDatagramsQueueSize, nil)
	newChannel.setDatagramSender(c.getDatagramSenderForChannel(newChannel.ChannelID()))

	// Server-initiated reverse-forward data channels carry the
	// server-side bind address in their header additional bytes
	// (see Conversation.OpenTCPReverseForwardingChannel and the
	// UDP variant).  Decode it here so the central client-side
	// dispatcher can route the channel by bind address.  Any
	// parse error means the peer is sending us malformed reverse-
	// forward channels; surface it instead of silently demoting
	// the channel to a generic one.
	switch channelInfo.ChannelType {
	case "cmxsafe-open-reverse-tcp-v1":
		bindIP, bindPort, peerIP, peerPort, err := parseCMXsafeReverseOpenHeader(channelInfo.ChannelID, &StreamByteReader{stream})
		if err != nil {
			log.Error().Msgf("parse CMXsafe reverse TCP header: %s", err)
			return err
		}
		c.channelsAcceptQueue.Add(&TCPOpenReverseForwardingChannelImpl{Channel: newChannel, BindAddr: &net.TCPAddr{IP: bindIP, Port: int(bindPort)}, PeerAddr: &net.TCPAddr{IP: peerIP, Port: int(peerPort)}})
		return nil
	case "cmxsafe-open-reverse-udp-v1":
		bindIP, bindPort, peerIP, peerPort, err := parseCMXsafeReverseOpenHeader(channelInfo.ChannelID, &StreamByteReader{stream})
		if err != nil {
			log.Error().Msgf("parse CMXsafe reverse UDP header: %s", err)
			return err
		}
		c.channelsAcceptQueue.Add(&UDPOpenReverseForwardingChannelImpl{Channel: newChannel, BindAddr: &net.UDPAddr{IP: bindIP, Port: int(bindPort)}, PeerAddr: &net.UDPAddr{IP: peerIP, Port: int(peerPort)}})
		return nil
	case "open-request-reverse-tcp", "open-request-reverse-udp":
		return fmt.Errorf("legacy reverse-open channel %q rejected: CMXsafe v1 peer tuple is required", channelInfo.ChannelType)
	}

	c.channelsAcceptQueue.Add(newChannel)
	return nil
}

func parseSSHChannelHeader(stream *quic.Stream) (uint64, string, uint64, error) {
	reader := &StreamByteReader{stream}
	frameType, err := util.ReadVarInt(reader)
	if err != nil {
		return 0, "", 0, err
	}
	if frameType != SSH_FRAME_TYPE {
		return 0, "", 0, fmt.Errorf("unexpected frame type %d", frameType)
	}
	return parseHeader(uint64(stream.StreamID()), reader)
}

func (c *Conversation) EstablishClientConversation(req *http.Request, rawClient *http3.RawClientConn, qconn *quic.Conn, supportedVersions []Version) error {
	var requestStream *http3.RequestStream

	doReq := func(version Version, req *http.Request) (*http.Response, Version, error) {
		req.Header.Set("User-Agent", version.GetVersionString())
		log.Debug().Msgf("send %s request on URL %s, User-Agent=\"%s\"", req.Method, req.URL, req.Header.Get("User-Agent"))
		stream, err := rawClient.OpenRequestStream(req.Context())
		if err != nil {
			return nil, Version{}, err
		}
		if err := stream.SendRequestHeader(req); err != nil {
			return nil, Version{}, err
		}
		rsp, err := stream.ReadResponse()
		if err != nil {
			return rsp, Version{}, err
		}
		requestStream = stream

		log.Debug().Msgf("got response with %s status code", rsp.Status)

		serverVersionStr := rsp.Header.Get("Server")
		serverVersion, err := ParseVersionString(serverVersionStr)
		if err != nil {
			log.Error().Msgf("Could not parse server version: \"%s\"", serverVersionStr)
			if rsp.StatusCode == 200 {
				return rsp, Version{}, InvalidSSHVersion{versionString: serverVersionStr}
			}
		} else {
			log.Debug().Msgf("server has valid version \"%s\" (protocol version = %s, software version = %s)",
				serverVersionStr, serverVersion.GetProtocolVersion(), serverVersion.GetSoftwareVersion())
		}
		return rsp, serverVersion, nil
	}

	rsp, serverVersion, err := doReq(ThisVersion(), req)
	if err != nil {
		return err
	}

	serverProtocolVersion := serverVersion.GetProtocolVersion()
	thisProtocolVersion := ThisVersion().GetProtocolVersion()
	if rsp.StatusCode == http.StatusForbidden && serverProtocolVersion != thisProtocolVersion {
		// This version negotiation code might feel a bit heavy but is only there for a smooth transition
		// between early versions and versions coming from an actual IETF specification that include
		// proper version negotiation. Older version of this implementation strictly check the exact protocol
		// version (i.e. must be 3.0) and then check the software version. In next iterations, everything will be
		// based on the protocol version for better interoperability.

		// see if there is an exact version match (including software version, which is useful
		// for old versions that do not support version negotiation based on the protocol version)
		matchingVersionIndex := slices.Index(supportedVersions, serverVersion)

		// there is no exact match, the implementation/software version might differ, but the
		// protocol version may still match
		if matchingVersionIndex == -1 {
			matchingVersionIndex = slices.IndexFunc(supportedVersions, func(supportedVersion Version) bool {
				return serverProtocolVersion == supportedVersion.GetProtocolVersion()
			})
		}
		if matchingVersionIndex != -1 {
			log.Warn().Msgf("The server runs an old version of the protocol (%s). This software is still experimental, "+
				"you may want to update the server version before support is removed. Also, note that connecting to old "+
				"servers may increase the connection establishment time.", serverVersion.GetVersionString())
			// now retry the request with the compatible version
			_ = rsp.Body.Close()
			_ = requestStream.Close()
			rsp, serverVersion, err = doReq(supportedVersions[matchingVersionIndex], req)
			if err != nil {
				return err
			}
		}
	}

	if rsp.StatusCode == 200 {
		if !IsVersionSupported(serverVersion) {
			log.Warn().Msgf("The server runs an unsupported SSH version (%s), you may want to consider to update the client (currently %s)",
				serverVersion.GetProtocolVersion(), ThisVersion().GetProtocolVersion())
		}
		c.controlStream = requestStream
		c.streamCreator = qconn
		c.messageSender = c.controlStream
		c.context, c.cancelContext = context.WithCancelCause(qconn.Context())
		go func() {
			for {
				dgram, err := c.controlStream.ReceiveDatagram(c.Context())
				if err != nil {
					if err != context.Canceled {
						log.Error().Msgf("could not receive message from conn: %s", err)
					}
					return
				}
				buf := &util.BytesReadCloser{Reader: bytes.NewReader(dgram)}
				convID, err := util.ReadVarInt(buf)
				if err != nil {
					log.Error().Msgf("could not read conv id from datagram on conv %d: %s", c.controlStream.StreamID(), err)
					return
				}
				if convID == uint64(c.controlStream.StreamID()) {
					err = c.AddDatagram(c.Context(), dgram[buf.Size()-int64(buf.Len()):])
					if err != nil {
						log.Error().Msgf("could not add datagram to conv id %d: %s", c.controlStream.StreamID(), err)
						return
					}
				} else {
					log.Error().Msgf("discarding datagram with invalid conv id %d", convID)
				}
			}
		}()
		go func() {
			for {
				stream, err := qconn.AcceptStream(c.Context())
				if err != nil {
					if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
						log.Error().Msgf("could not accept server-initiated channel: %s", err)
					}
					return
				}
				go func() {
					if err := c.handleIncomingChannel(stream); err != nil {
						log.Error().Msgf("could not handle server-initiated channel %d: %s", stream.StreamID(), err)
						stream.CancelRead(0)
						stream.CancelWrite(0)
					}
				}()
			}
		}()
		c.peerVersion = serverVersion
		// Servers predating the raw HTTP/3 API can send the 200 response before
		// their StreamHijacker registration becomes visible. They have no
		// protocol-level ready acknowledgement, so retain a short compatibility
		// grace period before opening the first SSH channel.
		if serverProtocolVersion != thisProtocolVersion {
			time.Sleep(50 * time.Millisecond)
		}
		return nil
	} else if rsp.StatusCode == http.StatusUnauthorized {
		_ = rsp.Body.Close()
		_ = requestStream.Close()
		return util.Unauthorized{}
	} else {
		bodyContent, err := io.ReadAll(rsp.Body)
		rsp.Body.Close()
		_ = requestStream.Close()
		if err != nil {
			log.Error().Msgf("could not read response body from server: %s", err)
		}

		return util.OtherHTTPError{
			HasBody:    rsp.ContentLength > 0,
			Body:       string(bodyContent),
			StatusCode: rsp.StatusCode,
		}
	}
}

func NewServerConversation(ctx context.Context, controlStream conversationStream, qconn *quic.Conn, messageSender util.DatagramSender, maxPacketsize uint64, peerVersion Version) (*Conversation, error) {
	tls := qconn.ConnectionState().TLS
	convID, err := GenerateConversationID(&tls)
	if err != nil {
		log.Error().Msgf("could not generate conversation ID on server")
		return nil, err
	}
	backgroundContext, backgroundCancelFunc := context.WithCancelCause(ctx)

	conv := &Conversation{
		controlStream:       controlStream,
		channelsAcceptQueue: util.NewAcceptQueue[Channel](),
		streamCreator:       qconn,
		maxPacketSize:       maxPacketsize,
		messageSender:       messageSender,
		channelsManager:     newChannelsManager(),
		context:             backgroundContext,
		cancelContext:       backgroundCancelFunc,
		conversationID:      convID,
		peerVersion:         peerVersion,
	}
	return conv, nil
}

func (c *Conversation) AttachServerControlStream(stream *http3.Stream) {
	c.controlStream = stream
	c.messageSender = stream
}

type StreamByteReader struct {
	*quic.Stream
}

func (r *StreamByteReader) ReadByte() (byte, error) {
	buf := [1]byte{0}
	_, err := r.Read(buf[:])
	if err != nil {
		return 0, err
	}
	return buf[0], nil
}

func (c *Conversation) OpenChannel(channelType string, maxPacketSize uint64, datagramsQueueSize uint64) (Channel, error) {
	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), channelType, maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, nil)
	c.channelsManager.addChannel(channel)
	return channel, nil
}

func (c *Conversation) OpenUDPForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.UDPAddr, remoteAddr *net.UDPAddr) (Channel, error) {

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	additionalBytes, err := buildCMXsafeDirectAdditionalBytes(uint16(localAddr.Port), remoteAddr.IP, uint16(remoteAddr.Port))
	if err != nil {
		return nil, err
	}

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "cmxsafe-direct-udp-v1", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.setDatagramSender(c.getDatagramSenderForChannel(channel.ChannelID()))
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &UDPForwardingChannelImpl{Channel: channel, RemoteAddr: remoteAddr, SourcePort: uint16(localAddr.Port)}, nil
}

func (c *Conversation) OpenTCPForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.TCPAddr, remoteAddr *net.TCPAddr) (Channel, error) {

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	additionalBytes, err := buildCMXsafeDirectAdditionalBytes(uint16(localAddr.Port), remoteAddr.IP, uint16(remoteAddr.Port))
	if err != nil {
		return nil, err
	}

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "cmxsafe-direct-tcp-v1", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &TCPForwardingChannelImpl{Channel: channel, RemoteAddr: remoteAddr, SourcePort: uint16(localAddr.Port)}, nil
}
func (c *Conversation) RequestTCPReverseChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.TCPAddr, remoteAddr *net.TCPAddr) (Channel, error) {
	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}

	additionalBytes := buildRequestReverseChannelAdditionalBytes(localAddr.IP, uint16(localAddr.Port), remoteAddr.IP, uint16(remoteAddr.Port))

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "request-reverse-tcp", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &TCPForwardingChannelImpl{Channel: channel, RemoteAddr: remoteAddr}, nil

}
func (c *Conversation) RequestUDPReverseChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.UDPAddr, remoteAddr *net.UDPAddr) (Channel, error) {
	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}

	additionalBytes := buildRequestReverseChannelAdditionalBytes(localAddr.IP, uint16(localAddr.Port), remoteAddr.IP, uint16(remoteAddr.Port))

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "request-reverse-udp", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &UDPForwardingChannelImpl{Channel: channel, LocalAddr: localAddr, RemoteAddr: remoteAddr}, nil

}

// OpenTCPReverseForwardingChannel opens a server-initiated data channel
// for one inbound connection on a previously-established reverse-TCP
// forward.  bindAddr is the server-side listening address that produced
// the connection: it is serialised into the channel-header additional
// bytes so the client-side dispatcher can route the channel to the
// matching reverse-forward handler.  Without this, multiple concurrent
// reverse-TCP forwards on the same conversation would be indistinguishable
// to the client and would race over each other.
func (c *Conversation) OpenTCPReverseForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, bindAddr, peerAddr *net.TCPAddr) (Channel, error) {

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}

	additionalBytes, err := buildCMXsafeReverseOpenAdditionalBytes(bindAddr.IP, uint16(bindAddr.Port), peerAddr.IP, uint16(peerAddr.Port))
	if err != nil {
		return nil, err
	}
	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "cmxsafe-open-reverse-tcp-v1", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &TCPOpenReverseForwardingChannelImpl{Channel: channel, BindAddr: bindAddr, PeerAddr: peerAddr}, nil
}

// OpenUDPReverseForwardingChannel is the UDP analogue of
// OpenTCPReverseForwardingChannel; see its doc for the role of bindAddr.
//
// Pre-existing PR #148 versions of this function encoded the addresses in
// the channel-type string itself ("open-request-reverse-udp,<local>,<remote>")
// because the additional-bytes path was not wired up.  We now use the
// regular additional-bytes header for one address (the bind side), which
// keeps the wire format consistent with the TCP variant and lets the
// client dispatcher reuse the same parser.
func (c *Conversation) OpenUDPReverseForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, bindAddr, peerAddr *net.UDPAddr) (Channel, error) {

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}

	additionalBytes, err := buildCMXsafeReverseOpenAdditionalBytes(bindAddr.IP, uint16(bindAddr.Port), peerAddr.IP, uint16(peerAddr.Port))
	if err != nil {
		return nil, err
	}
	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "cmxsafe-open-reverse-udp-v1", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.setDatagramSender(c.getDatagramSenderForChannel(channel.ChannelID()))
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &UDPOpenReverseForwardingChannelImpl{Channel: channel, BindAddr: bindAddr, PeerAddr: peerAddr}, nil
}

func (c *Conversation) AcceptChannel(ctx context.Context) (Channel, error) {
	for {
		if channel := c.channelsAcceptQueue.Next(); channel != nil {
			channel.confirmChannel(c.maxPacketSize)
			c.channelsManager.addChannel(channel)
			return channel, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.channelsAcceptQueue.Chan():
		}
	}

}

// blocks until the datagram is added
// the first field must be the channel ID
func (c *Conversation) AddDatagram(ctx context.Context, datagram []byte) error {
	buf := &util.BytesReadCloser{Reader: bytes.NewReader(datagram)}
	channelID, err := util.ReadVarInt(buf)
	if err != nil {
		return err
	}
	channel, ok := c.channelsManager.getChannel(channelID)
	if !ok {
		dgramQueue := util.NewDatagramsQueue(10)
		dgramQueue.Add(datagram[buf.Size()-int64(buf.Len()):])
		c.channelsManager.addDanglingDatagramsQueue(channelID, dgramQueue)
		return util.ChannelNotFound{ChannelID: channelID}
	}
	return channel.waitAddDatagram(ctx, datagram[buf.Size()-int64(buf.Len()):])
}

func (c *Conversation) Close() {
	c.controlStream.Close()
	c.cancelContext(nil)
}

func (c *Conversation) Context() context.Context {
	return c.context
}

func (c *Conversation) getDatagramSenderForChannel(channelID util.ChannelID) func(datagram []byte) error {
	return func(datagram []byte) error {
		buf := util.AppendVarInt(nil, uint64(c.controlStream.StreamID()))
		buf = util.AppendVarInt(buf, channelID)
		buf = append(buf, datagram...)
		return c.messageSender.SendDatagram(buf)
	}
}

func (c *Conversation) ConversationID() ConversationID {
	return c.conversationID
}
