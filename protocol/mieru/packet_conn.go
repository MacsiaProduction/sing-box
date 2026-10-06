package mieru

import (
	"bytes"
	"net"
	"os"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
)

// Preserve domain addresses instead of converting them to IP-only UDPAddr values.
type udpAssociatePacketConn struct {
	*mierucommon.UDPAssociateWrapper
}

var _ N.NetPacketConn = (*udpAssociatePacketConn)(nil)

func newUDPAssociatePacketConn(conn net.Conn) *udpAssociatePacketConn {
	return &udpAssociatePacketConn{mierucommon.NewUDPAssociateWrapper(mierucommon.NewPacketOverStreamTunnel(conn))}
}

func (c *udpAssociatePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, address, err := c.ReadFrom(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNet(address).Unwrap(), nil
}

// Mieru's wrapper rejects domain replies; parse its header without resolving them.
func (c *udpAssociatePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	packet := make([]byte, len(p)+3+M.MaxSocksaddrLength)
	n, _, err := c.PacketConn.ReadFrom(packet)
	if err != nil {
		return 0, nil, err
	}
	if n < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return 0, nil, os.ErrInvalid
	}
	reader := bytes.NewReader(packet[3:n])
	var address mierumodel.NetAddrSpec
	if err := address.ReadFromSocks5(reader); err != nil {
		return 0, nil, err
	}
	if len(address.IP) == 0 && address.FQDN == "" {
		return 0, nil, os.ErrInvalid
	}
	n = copy(p, packet[n-reader.Len():n])
	if address.FQDN != "" {
		return n, M.Socksaddr{Fqdn: address.FQDN, Port: uint16(address.Port)}, nil
	}
	return n, &net.UDPAddr{IP: address.IP, Port: address.Port}, nil
}

func (c *udpAssociatePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	// Mieru ignores serialization errors for an empty destination.
	if !destination.IsValid() {
		return os.ErrInvalid
	}
	_, err := c.WriteTo(buffer.Bytes(), destination)
	return err
}
