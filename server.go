package ssh3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3/util"
)

type ServerConversationHandler func(authenticatedUsername string, conversation *Conversation) error

type quicConnContextKey struct{}

func ConnectionFromContext(ctx context.Context) (*quic.Conn, bool) {
	conn, ok := ctx.Value(quicConnContextKey{}).(*quic.Conn)
	return conn, ok
}

type Server struct {
	maxPacketSize       uint64
	h3Server            *http3.Server
	conversations       map[*quic.Conn]*conversationsManager
	conversationHandler ServerConversationHandler
	lock                sync.Mutex
	// conversations map[]
}

// Creates a new server handling http requests for SSH conversations

func NewServer(maxPacketSize uint64, defaultDatagramQueueSize uint64, h3Server *http3.Server, conversationHandler ServerConversationHandler) *Server {
	previousConnContext := h3Server.ConnContext
	h3Server.ConnContext = func(ctx context.Context, conn *quic.Conn) context.Context {
		if previousConnContext != nil {
			ctx = previousConnContext(ctx, conn)
		}
		return context.WithValue(ctx, quicConnContextKey{}, conn)
	}
	ssh3Server := &Server{
		maxPacketSize:       maxPacketSize,
		h3Server:            h3Server,
		conversations:       make(map[*quic.Conn]*conversationsManager),
		conversationHandler: conversationHandler,
	}

	return ssh3Server
}

func (s *Server) getConversationsManager(streamCreator *quic.Conn) (*conversationsManager, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	conversations, ok := s.conversations[streamCreator]
	return conversations, ok
}

func (s *Server) getOrCreateConversationsManager(streamCreator *quic.Conn) *conversationsManager {
	s.lock.Lock()
	defer s.lock.Unlock()
	conversationsManager, ok := s.conversations[streamCreator]
	if !ok {
		s.conversations[streamCreator] = newConversationManager(streamCreator)
		conversationsManager = s.conversations[streamCreator]
	}
	return conversationsManager
}

func (s *Server) removeConnection(streamCreator *quic.Conn) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.conversations, streamCreator)
}

func (s *Server) handleIncomingChannel(qconn *quic.Conn, stream *quic.Stream, defaultDatagramQueueSize uint64) error {
	conversationControlStreamID, channelType, maxPacketSize, err := parseSSHChannelHeader(stream)
	if err != nil {
		return err
	}
	var conversation *Conversation
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	retry := time.NewTicker(time.Millisecond)
	defer retry.Stop()
	for conversation == nil {
		if manager, ok := s.getConversationsManager(qconn); ok {
			conversation, _ = manager.getConversation(conversationControlStreamID)
		}
		if conversation != nil {
			break
		}
		select {
		case <-qconn.Context().Done():
			return context.Cause(qconn.Context())
		case <-deadline.C:
			return fmt.Errorf("timed out waiting for SSH3 conversation %d for channel %d", conversationControlStreamID, stream.StreamID())
		case <-retry.C:
		}
	}
	channelInfo := &ChannelInfo{ConversationID: conversation.conversationID, ConversationStreamID: conversationControlStreamID, ChannelID: uint64(stream.StreamID()), ChannelType: channelType, MaxPacketSize: maxPacketSize}
	newChannel := NewChannel(channelInfo.ConversationStreamID, channelInfo.ConversationID, channelInfo.ChannelID, channelInfo.ChannelType, channelInfo.MaxPacketSize, &StreamByteReader{stream}, stream, nil, conversation.channelsManager, false, false, true, defaultDatagramQueueSize, nil)
	switch channelInfo.ChannelType {
	case "cmxsafe-direct-udp-v1":
		sourcePort, ip, port, err := parseCMXsafeDirectHeader(channelInfo.ChannelID, &StreamByteReader{stream})
		if err != nil {
			return err
		}
		newChannel.setDatagramSender(conversation.getDatagramSenderForChannel(channelInfo.ChannelID))
		newChannel = &UDPForwardingChannelImpl{Channel: newChannel, RemoteAddr: &net.UDPAddr{IP: ip, Port: int(port)}, SourcePort: sourcePort}
	case "cmxsafe-direct-tcp-v1":
		sourcePort, ip, port, err := parseCMXsafeDirectHeader(channelInfo.ChannelID, &StreamByteReader{stream})
		if err != nil {
			return err
		}
		newChannel = &TCPForwardingChannelImpl{Channel: newChannel, RemoteAddr: &net.TCPAddr{IP: ip, Port: int(port)}, SourcePort: sourcePort}
	case "direct-tcp", "direct-udp":
		return fmt.Errorf("legacy direct-forward channel %q rejected: CMXsafe v1 source port is required", channelInfo.ChannelType)
	case "request-reverse-tcp":
		local, remote, err := parseTCPRequestReverseHeader(channelInfo.ChannelID, &StreamByteReader{stream})
		if err != nil {
			return err
		}
		newChannel = &TCPReverseForwardingChannelImpl{Channel: newChannel, RemoteAddr: remote, LocalAddr: local}
	case "request-reverse-udp":
		local, remote, err := parseUDPRequestReverseHeader(channelInfo.ChannelID, &StreamByteReader{stream})
		if err != nil {
			return err
		}
		newChannel = &UDPReverseForwardingChannelImpl{Channel: newChannel, RemoteAddr: remote, LocalAddr: local}
	}
	conversation.channelsAcceptQueue.Add(newChannel)
	return nil
}

func (s *Server) ListenAndServe(defaultDatagramQueueSize uint64) error {
	listener, err := quic.ListenAddr(s.h3Server.Addr, http3.ConfigureTLSConfig(s.h3Server.TLSConfig), s.h3Server.QUICConfig)
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.serveConnection(conn, defaultDatagramQueueSize)
	}
}

func (s *Server) serveConnection(conn *quic.Conn, defaultDatagramQueueSize uint64) {
	raw, err := s.h3Server.NewRawServerConn(conn)
	if err != nil {
		log.Error().Err(err).Msg("create raw HTTP/3 connection")
		return
	}
	go func() {
		for {
			stream, err := conn.AcceptUniStream(conn.Context())
			if err != nil {
				return
			}
			go raw.HandleUnidirectionalStream(stream)
		}
	}()
	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		frameType, err := quicvarint.Peek(stream)
		if err != nil {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			continue
		}
		switch frameType {
		case 0x1: // HTTP/3 HEADERS
			go raw.HandleRequestStream(stream)
		case SSH_FRAME_TYPE:
			go func() {
				if err := s.handleIncomingChannel(conn, stream, defaultDatagramQueueSize); err != nil {
					log.Error().Err(err).Uint64("stream_id", uint64(stream.StreamID())).Msg("handle SSH3 channel")
					stream.CancelRead(0)
					stream.CancelWrite(0)
				}
			}()
		default:
			log.Error().Uint64("frame_type", frameType).Msg("reject unknown bidirectional stream")
			stream.CancelRead(0)
			stream.CancelWrite(0)
		}
	}
}

type AuthenticatedHandlerFunc func(authenticatedUserName string, newConv *Conversation, w http.ResponseWriter, r *http.Request)

type UnauthenticatedBearerFunc func(unauthenticatedBearerString string, base64ConversationID string, w http.ResponseWriter, r *http.Request)

func (s *Server) GetHTTPHandlerFunc(ctx context.Context) AuthenticatedHandlerFunc {

	return func(authenticatedUsername string, newConv *Conversation, w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("got request: method: %s, URL: %s", r.Method, r.URL.String())
		if r.Method == http.MethodConnect && r.Proto == "ssh3" {
			qconn := newConv.streamCreator
			conversationsManager := s.getOrCreateConversationsManager(qconn)
			conversationsManager.addConversation(newConv)

			w.WriteHeader(200)

			go func() {
				for {
					dgram, err := newConv.controlStream.ReceiveDatagram(ctx)
					if err != nil {
						if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
							log.Error().Msgf("could not receive message from conn: %s", err)
						}
						return
					}
					buf := &util.BytesReadCloser{Reader: bytes.NewReader(dgram)}
					convID, err := util.ReadVarInt(buf)
					if err != nil || convID != uint64(newConv.controlStream.StreamID()) {
						log.Error().Msgf("discarding datagram with invalid conversation id %d", convID)
						continue
					}
					if err = newConv.AddDatagram(ctx, dgram[buf.Size()-int64(buf.Len()):]); err != nil {
						switch e := err.(type) {
						case util.ChannelNotFound:
							log.Warn().Msgf("could not find channel %d, queue datagram in the meantime", e.ChannelID)
						default:
							log.Error().Msgf("could not add datagram to conv id %d: %s", newConv.controlStream.StreamID(), err)
							return
						}
					}
				}
			}()
			go func() {
				defer newConv.Close()
				defer conversationsManager.removeConversation(newConv)
				defer s.removeConnection(qconn)
				if err := s.conversationHandler(authenticatedUsername, newConv); err != nil {
					if errors.Is(err, context.Canceled) {
						log.Info().Msgf("conversation canceled for conversation id %s, user %s", newConv.ConversationID(), authenticatedUsername)
					} else {
						log.Error().Msgf("error while handing new conversation: %s for user %s: %s", newConv.ConversationID(), authenticatedUsername, err)
					}
					return
				}
			}()
		}
	}
}
