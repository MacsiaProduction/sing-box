package mieru

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"

	mieruclient "github.com/enfein/mieru/v3/apis/client"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
)

// Replace only the encrypted transport. Both actual Outbound UDP constructors,
// PacketOverStreamTunnel, UDPAssociateWrapper, bufio and Group stay in the path.
type proofStream struct {
	written []byte
	reply   *bytes.Reader
}

func (s *proofStream) Write(p []byte) (int, error) {
	s.written = append(s.written, p...)
	return len(p), nil
}
func (s *proofStream) Read(p []byte) (int, error) {
	if s.reply == nil {
		return 0, io.EOF
	}
	return s.reply.Read(p)
}
func (*proofStream) Close() error                     { return nil }
func (*proofStream) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*proofStream) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*proofStream) SetDeadline(time.Time) error      { return nil }
func (*proofStream) SetReadDeadline(time.Time) error  { return nil }
func (*proofStream) SetWriteDeadline(time.Time) error { return nil }

type proofClient struct {
	mieruclient.Client
	stream *proofStream
}

func (c *proofClient) DialContext(context.Context, net.Addr) (net.Conn, error) {
	return c.stream, nil
}

func proofOutbound(stream *proofStream) *Outbound {
	return &Outbound{logger: log.NewNOPFactory().Logger(), client: &proofClient{stream: stream}}
}

// Independent valid SOCKS address serialization; never pass through bufio.
func proofFrame(t *testing.T, destination M.Socksaddr, payload []byte) []byte {
	t.Helper()
	var address mierumodel.NetAddrSpec
	if err := address.From(destination); err != nil {
		t.Fatal(err)
	}
	var packet bytes.Buffer
	packet.Write([]byte{0, 0, 0})
	if err := address.WriteToSocks5(&packet); err != nil {
		t.Fatal(err)
	}
	packet.Write(payload)
	return proofStreamFrame(packet.Bytes())
}

func proofStreamFrame(packet []byte) []byte {
	frame := make([]byte, 4+len(packet))
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(packet)))
	copy(frame[3:], packet)
	frame[len(frame)-1] = 0xff
	return frame
}

func TestMieruInvalidUDPReply(t *testing.T) {
	for name, packet := range map[string][]byte{
		"short_header":     {0, 0},
		"reserved":         {1, 0, 0, 1, 127, 0, 0, 1, 0, 53},
		"fragment":         {0, 0, 1, 1, 127, 0, 0, 1, 0, 53},
		"unknown_address":  {0, 0, 0, 0xff, 0, 53},
		"empty_domain":     {0, 0, 0, 3, 0, 0, 53},
		"truncated_ipv4":   {0, 0, 0, 1, 127, 0},
		"truncated_ipv6":   {0, 0, 0, 4, 0},
		"truncated_domain": {0, 0, 0, 3, 4, 'a'},
		"truncated_port":   {0, 0, 0, 3, 1, 'a', 0},
	} {
		t.Run(name, func(t *testing.T) {
			stream := &proofStream{reply: bytes.NewReader(proofStreamFrame(packet))}
			conn, err := proofOutbound(stream).ListenPacket(context.Background(), M.ParseSocksaddr("guard.example:53"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, _, err := conn.ReadFrom(make([]byte, 64)); err == nil {
				t.Fatal("invalid reply accepted")
			}
		})
	}
}

func TestMieruUDPAddressLimits(t *testing.T) {
	for _, destination := range []M.Socksaddr{{}, {Fqdn: strings.Repeat("a", 256), Port: 53}} {
		stream := &proofStream{}
		conn, err := proofOutbound(stream).ListenPacket(context.Background(), M.ParseSocksaddr("guard.example:53"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := bufio.NewPacketConn(conn).WritePacket(buf.As([]byte("payload")), destination); err == nil || len(stream.written) != 0 {
			t.Fatalf("invalid destination sent: err=%v frame=%x", err, stream.written)
		}
	}
	destination := M.Socksaddr{Fqdn: strings.Repeat("a", 255), Port: 53}
	expected := proofFrame(t, destination, []byte("payload"))
	stream := &proofStream{reply: bytes.NewReader(expected)}
	conn, err := proofOutbound(stream).DialContext(context.Background(), "udp", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("payload")); err != nil || !bytes.Equal(stream.written, expected) {
		t.Fatalf("maximum domain write: %v", err)
	}
	buffer := make([]byte, 7)
	if n, err := conn.Read(buffer); err != nil || n != 7 || string(buffer) != "payload" {
		t.Fatalf("maximum domain reply: n=%d err=%v", n, err)
	}
	expected = proofFrame(t, M.ParseSocksaddr("guard.example:53"), []byte("payload"))
	stream.reply = bytes.NewReader(append(expected, expected...))
	if n, err := conn.Read(buffer[:3]); err != nil || n != 3 || string(buffer[:3]) != "pay" {
		t.Fatalf("short read: n=%d err=%v", n, err)
	}
	if n, err := conn.Read(buffer); err != nil || n != 7 || string(buffer) != "payload" {
		t.Fatalf("next packet after short read: n=%d err=%v", n, err)
	}
}

func TestMieruDomainUDP(t *testing.T) {
	payload := []byte("payload")
	for _, address := range []string{"guard.example:53", "198.18.0.8:53", "[2001:db8::8]:53"} {
		destination := M.ParseSocksaddr(address)
		for depth := 0; depth <= 2; depth++ {
			for _, direction := range []string{"write", "read"} {
				t.Run(fmt.Sprintf("%s/depth%d/%s", address, depth, direction), func(t *testing.T) {
					expected := proofFrame(t, destination, payload)
					stream := &proofStream{reply: bytes.NewReader(expected)}
					packet, err := proofOutbound(stream).ListenPacket(context.Background(), destination)
					if err != nil {
						t.Fatal(err)
					}
					for level := 0; level < depth; level++ {
						packet = interrupt.NewGroup().NewPacketConn(packet, false)
					}
					t.Cleanup(func() { packet.Close() })
					conn := bufio.NewPacketConn(packet)
					if direction == "write" {
						if err := conn.WritePacket(buf.As(payload), destination); err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(stream.written, expected) {
							t.Fatalf("SOCKS frame changed: got %x want %x", stream.written, expected)
						}
					} else {
						buffer := buf.NewPacket()
						defer buffer.Release()
						actual, err := conn.ReadPacket(buffer)
						if err != nil {
							t.Fatalf("valid reply rejected: %v", err)
						}
						if actual != destination || !bytes.Equal(buffer.Bytes(), payload) {
							t.Fatalf("reply changed: got %v %x want %v %x", actual, buffer.Bytes(), destination, payload)
						}
					}
				})
			}
		}
		t.Run(address+"/connected", func(t *testing.T) {
			expected := proofFrame(t, destination, payload)
			stream := &proofStream{reply: bytes.NewReader(expected)}
			conn, err := proofOutbound(stream).DialContext(context.Background(), "udp", destination)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stream.written, expected) {
				t.Fatalf("connected write changed: %x", stream.written)
			}
			buffer := make([]byte, len(payload))
			n, err := conn.Read(buffer)
			if err != nil || n != len(payload) || !bytes.Equal(buffer, payload) {
				t.Fatalf("valid connected reply rejected/changed: n=%d err=%v", n, err)
			}
		})
	}
}
