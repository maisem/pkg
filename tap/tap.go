// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tap registers Tailscale's experimental (demo) Linux TAP (Layer 2) support.
//go:build linux

package tap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tstun"
	"tailscale.com/syncs"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/util/multierr"
)

// TODO: this was randomly generated once. Maybe do it per process start? But
// then an upgraded tailscaled would be visible to devices behind it. So
// maybe instead make it a function of the tailscaled's wireguard public key?
// For now just hard code it.
var ourMAC = net.HardwareAddr{0x30, 0x2D, 0x66, 0xEC, 0x7A, 0x93}

var (
	routerLinkLocalAddr = netip.MustParseAddr("fe80::322d:66ff:feec:7a93")
	allNodesMulticast   = netip.MustParseAddr("ff02::1")
)

const (
	routerLifetimeSeconds          = 1800
	prefixValidLifetimeSeconds     = 7200
	prefixPreferredLifetimeSeconds = 3600
	routerAdvertisementInterval    = 200 * time.Second
)

const tapDebug = tstun.TAPDebug

func init() {
	tstun.CreateTAP.Set(createTAPLinux)
}

func createTAPLinux(logf logger.Logf, tapName, bridgeName string) (tun.Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	dev, err := openDevice(logf, fd, tapName, bridgeName)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	return dev, nil
}

func openDevice(logf logger.Logf, fd int, tapName, bridgeName string) (tun.Device, error) {
	ifr, err := unix.NewIfreq(tapName)
	if err != nil {
		return nil, err
	}

	// Flags are stored as a uint16 in the ifreq union.
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return nil, err
	}

	if err := run("ip", "link", "set", "dev", tapName, "up"); err != nil {
		return nil, err
	}
	if bridgeName != "" {
		if err := run("brctl", "addif", bridgeName, tapName); err != nil {
			return nil, err
		}
	}

	return newTAPDevice(logf, fd, tapName)
}

type etherType [2]byte

var (
	etherTypeARP  = etherType{0x08, 0x06}
	etherTypeIPv4 = etherType{0x08, 0x00}
	etherTypeIPv6 = etherType{0x86, 0xDD}
)

const (
	ipv4HeaderLen     = 20
	ipv6HeaderLen     = 40
	ethernetFrameSize = 14 // 2 six byte MACs, 2 bytes ethertype
)

const (
	consumePacket = true
	passOnPacket  = false
)

// handleTAPFrame handles receiving a raw TAP ethernet frame and reports whether
// it's been handled (that is, whether it should NOT be passed to wireguard).
func (t *tapDevice) handleTAPFrame(ethBuf []byte) bool {

	if len(ethBuf) < ethernetFrameSize {
		// Corrupt. Ignore.
		if tapDebug {
			t.logf("tap: short TAP frame")
		}
		return consumePacket
	}
	ethDstMAC, ethSrcMAC := ethBuf[:6], ethBuf[6:12]
	_ = ethDstMAC
	et := etherType{ethBuf[12], ethBuf[13]}
	switch et {
	default:
		if tapDebug {
			t.logf("tap: ignoring etherType %v", et)
		}
		return consumePacket // filter out packet we should ignore
	case etherTypeIPv6:
		// TODO: support DHCPv6/ND/etc later. For now pass all to WireGuard.
		if len(ethBuf) < ethernetFrameSize+ipv6HeaderLen {
			if tapDebug {
				t.logf("tap: short ipv6")
			}
			return consumePacket
		}
		return t.handleDHCPv6Request(ethBuf)
	case etherTypeIPv4:
		if len(ethBuf) < ethernetFrameSize+ipv4HeaderLen {
			// Bogus IPv4. Eat.
			if tapDebug {
				t.logf("tap: short ipv4")
			}
			return consumePacket
		}
		return t.handleDHCPv4Request(ethBuf)
	case etherTypeARP:
		arpPacket := header.ARP(ethBuf[ethernetFrameSize:])
		if !arpPacket.IsValid() {
			// Bogus ARP. Eat.
			return consumePacket
		}
		switch arpPacket.Op() {
		case header.ARPRequest:
			req := arpPacket // better name at this point
			buf := make([]byte, header.EthernetMinimumSize+header.ARPSize)

			// Our ARP "Table" of one:
			var srcMAC [6]byte
			copy(srcMAC[:], ethSrcMAC)
			if old := t.destMAC(); old != srcMAC {
				t.destMACAtomic.Store(srcMAC)
			}

			eth := header.Ethernet(buf)
			eth.Encode(&header.EthernetFields{
				SrcAddr: tcpip.LinkAddress(ourMAC[:]),
				DstAddr: tcpip.LinkAddress(ethSrcMAC),
				Type:    0x0806, // arp
			})
			res := header.ARP(buf[header.EthernetMinimumSize:])
			res.SetIPv4OverEthernet()
			res.SetOp(header.ARPReply)

			// If the client's asking about their own IP, tell them it's
			// their own MAC. TODO(bradfitz): remove String allocs.
			if net.IP(req.ProtocolAddressTarget()).String() == t.clientIPv4.Load() {
				copy(res.HardwareAddressSender(), ethSrcMAC)
			} else {
				copy(res.HardwareAddressSender(), ourMAC[:])
			}

			copy(res.ProtocolAddressSender(), req.ProtocolAddressTarget())
			copy(res.HardwareAddressTarget(), req.HardwareAddressSender())
			copy(res.ProtocolAddressTarget(), req.ProtocolAddressSender())

			n, err := t.WriteEthernet(buf)
			if tapDebug {
				t.logf("tap: wrote ARP reply %v, %v", n, err)
			}
		}

		return consumePacket
	}
}

var (
	// routerIP is the IP address of the DHCP server.
	routerIP   = net.ParseIP(tsaddr.TailscaleServiceIPString)
	routerIPv6 = net.ParseIP(tsaddr.TailscaleServiceIPv6String)
	// cgnatNetMask is the netmask of the 100.64.0.0/10 CGNAT range.
	cgnatNetMask = net.IPMask(net.ParseIP("255.192.0.0").To4())
	// serverDUID is the DUID for the DHCPv6 server (DUID-LL based on MAC).
	serverDUID = &dhcpv6.DUIDLL{HWType: 1, LinkLayerAddr: ourMAC}
)

// parsedPacketPool holds a pool of Parsed structs for use in filtering.
// This is needed because escape analysis cannot see that parsed packets
// do not escape through {Pre,Post}Filter{In,Out}.
var parsedPacketPool = sync.Pool{New: func() any { return new(packet.Parsed) }}

// handleRouterSolicitation responds to ICMPv6 Router Solicitation with a Router Advertisement
// that tells clients to use DHCPv6 for address configuration.
func (t *tapDevice) handleRouterSolicitation(ethBuf, ethSrcMAC []byte, p *packet.Parsed) bool {
	_ = ethBuf
	if tapDebug {
		t.logf("tap: Router Solicitation from %v", p.Src.Addr())
	}

	dstAddr := p.Src.Addr()
	if !dstAddr.IsValid() || dstAddr.IsUnspecified() {
		dstAddr = allNodesMulticast
	}
	if err := t.sendRouterAdvertisement(dstAddr, net.HardwareAddr(ethSrcMAC)); err != nil && tapDebug {
		t.logf("tap: sending Router Advertisement failed: %v", err)
	}

	return consumePacket
}

func (t *tapDevice) sendRouterAdvertisement(dstAddr netip.Addr, dstMAC net.HardwareAddr) error {
	// Build Router Advertisement with M=1 (use DHCPv6 for addresses) and O=1 (use DHCPv6 for other config)
	// RA format: CurHopLimit(1) + Flags(1) + RouterLifetime(2) + ReachableTime(4) + RetransTimer(4) = 12 bytes minimum
	// Plus Source Link-Layer Address option: Type(1) + Length(1) + MAC(6) = 8 bytes
	// Plus Prefix Information option: Type(1) + Length(1) + ... = 32 bytes

	const (
		sllaOptionLen   = 8
		prefixInfoLen   = 32
		icmpv6HeaderLen = 4
	)

	raBody := make([]byte, header.NDPRAMinimumSize+sllaOptionLen+prefixInfoLen)

	// Cur Hop Limit
	raBody[0] = 64

	// Flags: M=1 (bit 7), O=1 (bit 6) - tells client to use DHCPv6
	raBody[1] = 0xC0 // 11000000 in binary

	// Router Lifetime
	binary.BigEndian.PutUint16(raBody[2:4], routerLifetimeSeconds)

	// Reachable Time & Retrans Timer left as zero

	// Add Source Link-Layer Address (SLLA) option - required per RFC 4861
	// Type: 1 (Source Link-Layer Address)
	raBody[12] = 1
	// Length: 1 (in units of 8 octets, so 1 = 8 bytes total)
	raBody[13] = 1
	// Link-Layer Address: our MAC address
	copy(raBody[14:20], ourMAC)

	// Prefix Information option
	offset := 20
	// Type: 3 (Prefix Information)
	raBody[offset] = 3
	// Length: 4 (32 bytes)
	raBody[offset+1] = 4
	// Prefix Length: 64
	raBody[offset+2] = 64
	// Flags: L=1 (on-link), A=0 (no SLAAC, use DHCPv6)
	raBody[offset+3] = 0x80 // L=1 (on-link)
	binary.BigEndian.PutUint32(raBody[offset+4:offset+8], prefixValidLifetimeSeconds)
	binary.BigEndian.PutUint32(raBody[offset+8:offset+12], prefixPreferredLifetimeSeconds)
	prefixBytes := tsaddr.TailscaleULARange().Addr().As16()
	copy(raBody[offset+16:offset+32], prefixBytes[:])

	if !dstAddr.IsValid() || dstAddr.IsUnspecified() {
		dstAddr = allNodesMulticast
	}
	if dstMAC == nil {
		dstMAC = multicastMACForIPv6(dstAddr)
	}

	srcBytes := routerLinkLocalAddr.As16()
	dstBytes := dstAddr.As16()
	srcIP := tcpip.AddrFromSlice(srcBytes[:])
	dstIP := tcpip.AddrFromSlice(dstBytes[:])

	icmpv6Pkt := make([]byte, icmpv6HeaderLen+len(raBody))
	icmp := header.ICMPv6(icmpv6Pkt)
	icmp.SetType(header.ICMPv6RouterAdvert)
	icmp.SetCode(0)
	copy(icmpv6Pkt[icmpv6HeaderLen:], raBody)
	xsum := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmp,
		Src:         srcIP,
		Dst:         dstIP,
		PayloadCsum: 0,
		PayloadLen:  0,
	})
	icmp.SetChecksum(xsum)

	// Build full packet: Ethernet + IPv6 + ICMPv6
	pkt := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize+len(icmpv6Pkt))
	writeEthernetFrame(pkt, ourMAC, dstMAC, ipv6.ProtocolNumber)
	ipv6Hdr := header.IPv6(pkt[header.EthernetMinimumSize:])
	ipv6Hdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(icmpv6Pkt)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          255,
		SrcAddr:           srcIP,
		DstAddr:           dstIP,
	})
	copy(pkt[header.EthernetMinimumSize+header.IPv6MinimumSize:], icmpv6Pkt)

	_, err := t.WriteEthernet(pkt)
	if tapDebug {
		t.logf("tap: sent Router Advertisement to %v: %v", dstAddr, err)
	}
	return err
}

func multicastMACForIPv6(addr netip.Addr) net.HardwareAddr {
	mac := [6]byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x00}
	if addr.IsValid() {
		addrBytes := addr.As16()
		copy(mac[2:], addrBytes[12:])
	}
	return net.HardwareAddr(mac[:])
}

func (t *tapDevice) periodicRouterAdvertisements() {
	defer t.raWG.Done()

	ticker := time.NewTicker(routerAdvertisementInterval)
	defer ticker.Stop()

	// Send one immediately so clients joining late still see an RA.
	if err := t.sendRouterAdvertisement(allNodesMulticast, nil); err != nil && tapDebug {
		t.logf("tap: initial Router Advertisement failed: %v", err)
	}

	for {
		select {
		case <-t.raStop:
			return
		case <-ticker.C:
			if err := t.sendRouterAdvertisement(allNodesMulticast, nil); err != nil && tapDebug {
				t.logf("tap: periodic Router Advertisement failed: %v", err)
			}
		}
	}
}

// handleNeighborSolicitation responds to ICMPv6 Neighbor Solicitation with a Neighbor Advertisement
// containing the target's link-layer address (MAC).
func (t *tapDevice) handleNeighborSolicitation(ethBuf, ethSrcMAC []byte, p *packet.Parsed) bool {
	const icmpv6HeaderLen = 4
	const nsMinLen = icmpv6HeaderLen + 20 // 4 (reserved) + 16 (target address)

	if len(ethBuf) < ethernetFrameSize+ipv6HeaderLen+nsMinLen {
		return passOnPacket
	}

	// Parse NS message
	nsPayload := ethBuf[ethernetFrameSize+ipv6HeaderLen+icmpv6HeaderLen:]

	// Target Address is at offset 4 (after 4 bytes reserved field)
	targetAddr := netip.AddrFrom16(*(*[16]byte)(nsPayload[4:20]))

	if tapDebug {
		t.logf("tap: Neighbor Solicitation for %v from %v", targetAddr, p.Src.Addr())
	}

	// Check if the target is the client's IPv6 address
	ips := t.clientIPv6.Load()
	if ips == "" {
		return passOnPacket
	}
	clientIP, err := netip.ParseAddr(ips)
	if err != nil || (targetAddr.IsValid() && targetAddr == clientIP) {
		// Not soliciting for our client, pass through
		t.logf("tap: Neighbor Solicitation for %v from %v is for our client, passing through", targetAddr, p.Src.Addr())
		return passOnPacket
	}

	// Build Neighbor Advertisement
	// NA format: Flags(4) + TargetAddress(16) + Options
	// Flags: R=0, S=1, O=1 (Solicited=1, Override=1)
	// Option: Type(1) + Length(1) + LinkLayerAddr(6)
	// We respond with OUR MAC because we're the gateway for the client's IP
	const tllaOptionLen = 8
	const naBodyLen = 20 + tllaOptionLen // 4 (flags) + 16 (target) + 8 (TLLA option)
	naBody := make([]byte, naBodyLen)

	// Flags: S=1 (bit 30), O=1 (bit 29) in network byte order
	// 0x60000000 = 01100000 00000000 00000000 00000000
	binary.BigEndian.PutUint32(naBody[0:4], 0x60000000)

	// Target Address
	targetBytes := targetAddr.As16()
	copy(naBody[4:20], targetBytes[:])

	// Target Link-Layer Address (TLLA) option - use OUR MAC
	naBody[20] = 2 // Type: Target Link-Layer Address
	naBody[21] = 1 // Length: 1 (8 bytes)
	copy(naBody[22:28], ourMAC)

	// Build ICMPv6 packet
	icmpv6Pkt := make([]byte, icmpv6HeaderLen+len(naBody))
	icmp := header.ICMPv6(icmpv6Pkt)
	icmp.SetType(header.ICMPv6NeighborAdvert)
	icmp.SetCode(0)
	copy(icmpv6Pkt[icmpv6HeaderLen:], naBody)

	// Calculate ICMPv6 checksum
	// Source: target address (client's IPv6)
	// Destination: solicitor's address
	srcAddr := targetAddr
	dstAddr := p.Src.Addr()

	srcB := srcAddr.As16()
	srcIP := tcpip.AddrFromSlice(srcB[:])
	dstB := dstAddr.As16()
	dstIP := tcpip.AddrFromSlice(dstB[:])

	xsum := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmp,
		Src:         srcIP,
		Dst:         dstIP,
		PayloadCsum: 0,
		PayloadLen:  0, // Body already included in Header
	})
	icmp.SetChecksum(xsum)

	// Build full packet: Ethernet + IPv6 + ICMPv6
	pkt := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize+len(icmpv6Pkt))

	// Ethernet header: from our MAC to solicitor's MAC
	writeEthernetFrame(pkt, ourMAC, ethSrcMAC, ipv6.ProtocolNumber)

	// IPv6 header
	ipv6Hdr := header.IPv6(pkt[header.EthernetMinimumSize:])
	ipv6Hdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(icmpv6Pkt)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          255,
		SrcAddr:           srcIP,
		DstAddr:           dstIP,
	})

	// ICMPv6 body
	copy(pkt[header.EthernetMinimumSize+header.IPv6MinimumSize:], icmpv6Pkt)

	n, err := t.WriteEthernet(pkt)
	if tapDebug {
		t.logf("tap: wrote Neighbor Advertisement for %v with MAC %x, %v, %v", targetAddr, ourMAC, n, err)
	}

	return consumePacket
}

// handleDHCPv6Request handles receiving a raw TAP ethernet frame and reports whether
// it's been handled as a DHCPv6 request or NDP Router Solicitation. That is, it reports
// whether the frame should be ignored by the caller and not passed on.
func (t *tapDevice) handleDHCPv6Request(ethBuf []byte) bool {
	const icmpv6HeaderLen = 4
	if len(ethBuf) < ethernetFrameSize+ipv6HeaderLen+icmpv6HeaderLen {
		if tapDebug {
			t.logf("tap: IPv6 short")
		}
		return passOnPacket
	}
	ethDstMAC, ethSrcMAC := ethBuf[:6], ethBuf[6:12]
	_ = ethDstMAC

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	p.Decode(ethBuf[ethernetFrameSize:])

	// Check for ICMPv6 messages
	if p.IPProto == ipproto.ICMPv6 {
		icmpv6 := header.ICMPv6(ethBuf[ethernetFrameSize+ipv6HeaderLen:])
		switch icmpv6.Type() {
		case header.ICMPv6RouterSolicit:
			return t.handleRouterSolicitation(ethBuf, ethSrcMAC, p)
		case header.ICMPv6NeighborSolicit:
			return t.handleNeighborSolicitation(ethBuf, ethSrcMAC, p)
		default:
			// Other ICMPv6 (MLDv2, etc.) - pass through
			return passOnPacket
		}
	}

	// Check for DHCPv6 (UDP ports 546 -> 547)
	if p.IPProto != ipproto.UDP || p.Src.Port() != 546 || p.Dst.Port() != 547 {
		// Not DHCPv6 or ICMPv6 RS. Pass through to WireGuard.
		return passOnPacket
	}

	const udpHeader = 8
	if len(ethBuf) < ethernetFrameSize+ipv6HeaderLen+udpHeader {
		return passOnPacket
	}

	msg, err := dhcpv6.FromBytes(ethBuf[ethernetFrameSize+ipv6HeaderLen+udpHeader:])
	if err != nil {
		// Bogus. Trash it.
		if tapDebug {
			t.logf("tap: DHCPv6 FromBytes bad: %v", err)
		}
		return consumePacket
	}

	// Extract inner message if this is a relay message
	if msg.Type() == dhcpv6.MessageTypeRelayForward || msg.Type() == dhcpv6.MessageTypeRelayReply {
		inner, err := msg.GetInnerMessage()
		if err == nil {
			msg = inner
		}
	}

	if tapDebug {
		t.logf("tap: DHCPv6 request: %v", msg.Summary())
	}

	// Store the client's MAC address from DHCPv6 traffic so we can send packets to them
	var srcMAC [6]byte
	copy(srcMAC[:], ethSrcMAC)
	if old := t.destMAC(); old != srcMAC {
		t.destMACAtomic.Store(srcMAC)
		if tapDebug {
			t.logf("tap: stored client MAC from DHCPv6: %x", srcMAC)
		}
	}

	switch msg.Type() {
	case dhcpv6.MessageTypeSolicit:
		ips := t.clientIPv6.Load()
		if ips == "" {
			if tapDebug {
				t.logf("tap: DHCPv6 no client IPv6")
			}
			return consumePacket
		}
		clientIP := net.ParseIP(ips)
		if clientIP == nil {
			if tapDebug {
				t.logf("tap: DHCPv6 invalid client IPv6: %s", ips)
			}
			return consumePacket
		}

		// Extract IANA from client request to get IAID
		clientMsg := msg.(*dhcpv6.Message)
		ianas := clientMsg.Options.IANA()
		if len(ianas) == 0 {
			if tapDebug {
				t.logf("tap: DHCPv6 client did not request IANA")
			}
			return consumePacket
		}

		// Build response IANA with client's IAID and our address
		ianaOption := &dhcpv6.OptIANA{
			IaId: ianas[0].IaId,
			T1:   1800 * time.Second,
			T2:   2880 * time.Second,
		}
		ianaOption.Options.Add(&dhcpv6.OptIAAddress{
			IPv6Addr:          clientIP,
			PreferredLifetime: 3600 * time.Second,
			ValidLifetime:     7200 * time.Second,
		})

		// Build ADVERTISE or REPLY (if rapid commit)
		var reply *dhcpv6.Message
		if clientMsg.GetOneOption(dhcpv6.OptionRapidCommit) != nil {
			// Rapid commit: send REPLY directly
			reply, err = dhcpv6.NewReplyFromMessage(clientMsg,
				dhcpv6.WithServerID(serverDUID),
				dhcpv6.WithRapidCommit,
				dhcpv6.WithDNS(routerIPv6),
				dhcpv6.WithOption(ianaOption),
			)
		} else {
			// Normal flow: send ADVERTISE
			reply, err = dhcpv6.NewAdvertiseFromSolicit(clientMsg,
				dhcpv6.WithServerID(serverDUID),
				dhcpv6.WithDNS(routerIPv6),
				dhcpv6.WithOption(ianaOption),
			)
		}
		if err != nil {
			t.logf("error building DHCPv6 response: %v", err)
			return consumePacket
		}

		// Construct layer 2 packet
		pkt := packLayer2UDPv6(
			reply.ToBytes(),
			ourMAC, ethSrcMAC,
			netip.AddrPortFrom(netip.MustParseAddr(tsaddr.TailscaleServiceIPv6String), 547), // src
			netip.AddrPortFrom(p.Src.Addr(), 546),                                           // dst
		)

		n, err := t.WriteEthernet(pkt)
		if tapDebug {
			t.logf("tap: wrote DHCPv6 %v %v, %v", reply.Type(), n, err)
		}

	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeConfirm, dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind:
		ips := t.clientIPv6.Load()
		if ips == "" {
			if tapDebug {
				t.logf("tap: DHCPv6 no client IPv6")
			}
			return consumePacket
		}
		clientIP := net.ParseIP(ips)
		if clientIP == nil {
			if tapDebug {
				t.logf("tap: DHCPv6 invalid client IPv6: %s", ips)
			}
			return consumePacket
		}

		// Extract IANA from client request to get IAID
		clientMsg := msg.(*dhcpv6.Message)
		ianas := clientMsg.Options.IANA()
		if len(ianas) == 0 {
			if tapDebug {
				t.logf("tap: DHCPv6 client did not request IANA")
			}
			return consumePacket
		}

		// Build response IANA with client's IAID and our address
		ianaOption := &dhcpv6.OptIANA{
			IaId: ianas[0].IaId,
			T1:   1800 * time.Second,
			T2:   2880 * time.Second,
		}
		ianaOption.Options.Add(&dhcpv6.OptIAAddress{
			IPv6Addr:          clientIP,
			PreferredLifetime: 3600 * time.Second,
			ValidLifetime:     7200 * time.Second,
		})

		reply, err := dhcpv6.NewReplyFromMessage(clientMsg,
			dhcpv6.WithServerID(serverDUID),
			dhcpv6.WithDNS(routerIPv6),
			dhcpv6.WithOption(ianaOption),
		)
		if err != nil {
			t.logf("error building DHCPv6 reply: %v", err)
			return consumePacket
		}

		// Construct layer 2 packet
		pkt := packLayer2UDPv6(
			reply.ToBytes(),
			ourMAC, ethSrcMAC,
			netip.AddrPortFrom(netip.MustParseAddr(tsaddr.TailscaleServiceIPv6String), 547), // src
			netip.AddrPortFrom(p.Src.Addr(), 546),                                           // dst
		)

		n, err := t.WriteEthernet(pkt)
		if tapDebug {
			t.logf("tap: wrote DHCPv6 REPLY %v, %v", n, err)
		}

	default:
		if tapDebug {
			t.logf("tap: unknown DHCPv6 type: %v", msg.Type())
		}
	}
	return consumePacket
}

// handleDHCPv4Request handles receiving a raw TAP ethernet frame and reports whether
// it's been handled as a DHCP request. That is, it reports whether the frame should
// be ignored by the caller and not passed on.
func (t *tapDevice) handleDHCPv4Request(ethBuf []byte) bool {
	const udpHeader = 8
	if len(ethBuf) < ethernetFrameSize+ipv4HeaderLen+udpHeader {
		if tapDebug {
			t.logf("tap: DHCP short")
		}
		return passOnPacket
	}
	ethDstMAC, ethSrcMAC := ethBuf[:6], ethBuf[6:12]

	if string(ethDstMAC) != "\xff\xff\xff\xff\xff\xff" {
		// Not a broadcast
		if tapDebug {
			t.logf("tap: dhcp no broadcast")
		}
		return passOnPacket
	}

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	p.Decode(ethBuf[ethernetFrameSize:])

	if p.IPProto != ipproto.UDP || p.Src.Port() != 68 || p.Dst.Port() != 67 {
		// Not a DHCP request.
		if tapDebug {
			t.logf("tap: DHCP wrong meta: %+v", p)
		}
		return passOnPacket
	}

	dp, err := dhcpv4.FromBytes(ethBuf[ethernetFrameSize+ipv4HeaderLen+udpHeader:])
	if err != nil {
		// Bogus. Trash it.
		if tapDebug {
			t.logf("tap: DHCP FromBytes bad")
		}
		return consumePacket
	}
	if tapDebug {
		t.logf("tap: DHCP request: %+v", dp)
	}
	switch dp.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		ips := t.clientIPv4.Load()
		if ips == "" {
			t.logf("tap: DHCP no client IP")
			return consumePacket
		}
		offer, err := dhcpv4.New(
			dhcpv4.WithReply(dp),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
			dhcpv4.WithRouter(routerIP), // the default route
			dhcpv4.WithDNS(routerIP),
			dhcpv4.WithServerIP(routerIP), // TODO: what is this?
			dhcpv4.WithOption(dhcpv4.OptServerIdentifier(routerIP)),
			dhcpv4.WithYourIP(net.ParseIP(ips)),
			dhcpv4.WithLeaseTime(3600), // hour works
			//dhcpv4.WithHwAddr(ethSrcMAC),
			dhcpv4.WithNetmask(cgnatNetMask),
			//dhcpv4.WithTransactionID(dp.TransactionID),
		)
		if err != nil {
			t.logf("error building DHCP offer: %v", err)
			return consumePacket
		}
		// Make a layer 2 packet to write out:
		pkt := packLayer2UDP(
			offer.ToBytes(),
			ourMAC, ethSrcMAC,
			netip.AddrPortFrom(netaddr.IPv4(100, 100, 100, 100), 67), // src
			netip.AddrPortFrom(netaddr.IPv4(255, 255, 255, 255), 68), // dst
		)

		n, err := t.WriteEthernet(pkt)
		if tapDebug {
			t.logf("tap: wrote DHCP OFFER %v, %v", n, err)
		}
	case dhcpv4.MessageTypeRequest:
		ips := t.clientIPv4.Load()
		if ips == "" {
			t.logf("tap: DHCP no client IP")
			return consumePacket
		}
		ack, err := dhcpv4.New(
			dhcpv4.WithReply(dp),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
			dhcpv4.WithDNS(routerIP),
			dhcpv4.WithRouter(routerIP),   // the default route
			dhcpv4.WithServerIP(routerIP), // TODO: what is this?
			dhcpv4.WithOption(dhcpv4.OptServerIdentifier(routerIP)),
			dhcpv4.WithYourIP(net.ParseIP(ips)), // Hello world
			dhcpv4.WithLeaseTime(3600),          // hour works
			dhcpv4.WithNetmask(cgnatNetMask),
		)
		if err != nil {
			t.logf("error building DHCP ack: %v", err)
			return consumePacket
		}
		// Make a layer 2 packet to write out:
		pkt := packLayer2UDP(
			ack.ToBytes(),
			ourMAC, ethSrcMAC,
			netip.AddrPortFrom(netaddr.IPv4(100, 100, 100, 100), 67), // src
			netip.AddrPortFrom(netaddr.IPv4(255, 255, 255, 255), 68), // dst
		)
		n, err := t.WriteEthernet(pkt)
		if tapDebug {
			t.logf("tap: wrote DHCP ACK %v, %v", n, err)
		}
	default:
		if tapDebug {
			t.logf("tap: unknown DHCP type")
		}
	}
	return consumePacket
}

func writeEthernetFrame(buf []byte, srcMAC, dstMAC net.HardwareAddr, proto tcpip.NetworkProtocolNumber) {
	// Ethernet header
	eth := header.Ethernet(buf)
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(srcMAC),
		DstAddr: tcpip.LinkAddress(dstMAC),
		Type:    proto,
	})
}

func packLayer2UDP(payload []byte, srcMAC, dstMAC net.HardwareAddr, src, dst netip.AddrPort) []byte {
	buf := make([]byte, header.EthernetMinimumSize+header.UDPMinimumSize+header.IPv4MinimumSize+len(payload))
	payloadStart := len(buf) - len(payload)
	copy(buf[payloadStart:], payload)
	srcB := src.Addr().As4()
	srcIP := tcpip.AddrFromSlice(srcB[:])
	dstB := dst.Addr().As4()
	dstIP := tcpip.AddrFromSlice(dstB[:])
	// Ethernet header
	writeEthernetFrame(buf, srcMAC, dstMAC, ipv4.ProtocolNumber)
	// IP header
	ipbuf := buf[header.EthernetMinimumSize:]
	ip := header.IPv4(ipbuf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(ipbuf)),
		TTL:         65,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     srcIP,
		DstAddr:     dstIP,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	// UDP header
	u := header.UDP(buf[header.EthernetMinimumSize+header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, srcIP, dstIP, uint16(len(u)))
	// Calculate the UDP checksum and set it.
	xsum = checksum.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))
	return []byte(buf)
}

func packLayer2UDPv6(payload []byte, srcMAC, dstMAC net.HardwareAddr, src, dst netip.AddrPort) []byte {
	buf := make([]byte, header.EthernetMinimumSize+header.UDPMinimumSize+header.IPv6MinimumSize+len(payload))
	payloadStart := len(buf) - len(payload)
	copy(buf[payloadStart:], payload)
	srcB := src.Addr().As16()
	srcIP := tcpip.AddrFromSlice(srcB[:])
	dstB := dst.Addr().As16()
	dstIP := tcpip.AddrFromSlice(dstB[:])
	// Ethernet header
	writeEthernetFrame(buf, srcMAC, dstMAC, ipv6.ProtocolNumber)
	// IPv6 header
	ipbuf := buf[header.EthernetMinimumSize:]
	ip := header.IPv6(ipbuf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.UDPMinimumSize + len(payload)),
		TransportProtocol: udp.ProtocolNumber,
		HopLimit:          255,
		SrcAddr:           srcIP,
		DstAddr:           dstIP,
	})
	// UDP header
	u := header.UDP(buf[header.EthernetMinimumSize+header.IPv6MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, srcIP, dstIP, uint16(len(u)))
	// Calculate the UDP checksum and set it.
	xsum = checksum.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))
	return []byte(buf)
}

func run(prog string, args ...string) error {
	cmd := exec.Command(prog, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error running %v: %v", cmd, err)
	}
	return nil
}

func (t *tapDevice) destMAC() [6]byte {
	return t.destMACAtomic.Load()
}

func newTAPDevice(logf logger.Logf, fd int, tapName string) (tun.Device, error) {
	err := unix.SetNonblock(fd, true)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "/dev/tap")
	d := &tapDevice{
		logf:   logf,
		file:   file,
		events: make(chan tun.Event),
		name:   tapName,
		raStop: make(chan struct{}),
	}
	d.raWG.Add(1)
	go d.periodicRouterAdvertisements()
	return d, nil
}

type tapDevice struct {
	file       *os.File
	logf       func(format string, args ...any)
	events     chan tun.Event
	name       string
	closeOnce  sync.Once
	clientIPv4 syncs.AtomicValue[string]
	clientIPv6 syncs.AtomicValue[string]

	destMACAtomic syncs.AtomicValue[[6]byte]
	raStop        chan struct{}
	raWG          sync.WaitGroup
}

var _ tstun.SetIPer = (*tapDevice)(nil)

func (t *tapDevice) SetIP(ipV4, ipV6 netip.Addr) error {
	t.logf("tap: SetIP %v %v", ipV4, ipV6)
	if ipV4.IsValid() {
		t.clientIPv4.Store(ipV4.String())
	}
	if ipV6.IsValid() {
		t.clientIPv6.Store(ipV6.String())
	}
	return nil
}

func (t *tapDevice) File() *os.File {
	return t.file
}

func (t *tapDevice) Name() (string, error) {
	return t.name, nil
}

// Read reads an IP packet from the TAP device. It strips the ethernet frame header.
func (t *tapDevice) Read(buffs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.ReadEthernet(buffs, sizes, offset)
	if err != nil || n == 0 {
		return n, err
	}
	// Strip the ethernet frame header.
	copy(buffs[0][offset:], buffs[0][offset+ethernetFrameSize:offset+sizes[0]])
	sizes[0] -= ethernetFrameSize
	return 1, nil
}

// ReadEthernet reads a raw ethernet frame from the TAP device.
func (t *tapDevice) ReadEthernet(buffs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.file.Read(buffs[0][offset:])
	if err != nil {
		return 0, err
	}
	if t.handleTAPFrame(buffs[0][offset : offset+n]) {
		return 0, nil
	}
	sizes[0] = n
	return 1, nil
}

// WriteEthernet writes a raw ethernet frame to the TAP device.
func (t *tapDevice) WriteEthernet(buf []byte) (int, error) {
	return t.file.Write(buf)
}

// ethBufPool holds a pool of bytes.Buffers for use in [tapDevice.Write].
var ethBufPool = syncs.Pool[*bytes.Buffer]{New: func() *bytes.Buffer { return new(bytes.Buffer) }}

// Write writes a raw IP packet to the TAP device. It adds the ethernet frame header.
func (t *tapDevice) Write(buffs [][]byte, offset int) (int, error) {
	errs := make([]error, 0)
	wrote := 0
	m := t.destMAC()
	dstMac := net.HardwareAddr(m[:])
	if tapDebug {
		t.logf("tap: Write called with destMAC %x", m)
	}
	buf := ethBufPool.Get()
	defer ethBufPool.Put(buf)
	for _, buff := range buffs {
		buf.Reset()
		buf.Grow(header.EthernetMinimumSize + len(buff) - offset)

		var ethFrame [14]byte
		switch buff[offset] >> 4 {
		case 4:
			writeEthernetFrame(ethFrame[:], ourMAC, dstMac, ipv4.ProtocolNumber)
		case 6:
			writeEthernetFrame(ethFrame[:], ourMAC, dstMac, ipv6.ProtocolNumber)
		default:
			continue
		}
		buf.Write(ethFrame[:])
		buf.Write(buff[offset:])
		_, err := t.WriteEthernet(buf.Bytes())
		if err != nil {
			errs = append(errs, err)
		} else {
			wrote++
		}
	}
	return wrote, multierr.New(errs...)
}

func (t *tapDevice) MTU() (int, error) {
	ifr, err := unix.NewIfreq(t.name)
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(int(t.file.Fd()), unix.SIOCGIFMTU, ifr); err != nil {
		return 0, err
	}
	return int(ifr.Uint32()), nil
}

func (t *tapDevice) Events() <-chan tun.Event {
	return t.events
}

func (t *tapDevice) Close() error {
	var err error
	t.closeOnce.Do(func() {
		if t.raStop != nil {
			close(t.raStop)
			t.raWG.Wait()
		}
		close(t.events)
		err = t.file.Close()
	})
	return err
}

func (t *tapDevice) BatchSize() int {
	return 1
}
