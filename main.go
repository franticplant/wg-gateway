package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID tcpip.NICID = 1

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// verbose enables per-connection logging (set VERBOSE=1).
var verbose = os.Getenv("VERBOSE") != ""

// allowPrivate lets tunnel clients reach loopback, LAN and other
// non-public addresses of the host (set ALLOW_PRIVATE=1). Off by default.
var allowPrivate = os.Getenv("ALLOW_PRIVATE") != ""

var cgnat = &net.IPNet{
	IP:   net.IPv4(100, 64, 0, 0),
	Mask: net.CIDRMask(10, 32),
}

// blockedDestination reports whether a tunnel client may not reach ip.
// The gateway dials out from the host's network namespace, so without this
// a peer could reach the host's LAN, Tailscale, cloud metadata, etc.
func blockedDestination(ip net.IP) bool {
	if allowPrivate {
		return false
	}

	return ip == nil ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		cgnat.Contains(ip)
}

func debugf(format string, args ...any) {
	if verbose {
		log.Printf(format, args...)
	}
}

type netTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	done           chan struct{}
	mtu            int

	closeOnce sync.Once
}

/*
newNetTun constructs the plaintext side of WireGuard entirely in userspace.

WireGuard thinks this object is a TUN device.

But instead of /dev/net/tun:

	WireGuard decrypted IP packet
	    -> Write()
	    -> gVisor InjectInbound()

and:

	gVisor generated IP packet
	    -> channel.Endpoint
	    -> WriteNotify()
	    -> Read()
	    -> WireGuard encrypts it

No kernel TUN exists.
*/
func newNetTun(localIP string, mtu int) (*netTun, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
		// Must stay false: with promiscuous mode, HandleLocal makes gVisor
		// treat every peer source address as its own and drop the packets.
		HandleLocal: false,
	})

	ep := channel.New(2048, uint32(mtu), "")

	t := &netTun{
		ep:             ep,
		stack:          s,
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View, 2048),
		done:           make(chan struct{}),
		mtu:            mtu,
	}

	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("CreateNIC: %v", err)
	}

	addr := net.ParseIP(localIP).To4()
	if addr == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %s", localIP)
	}

	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{addr[0], addr[1], addr[2], addr[3]}),
			PrefixLen: 32,
		},
	}

	if err := s.AddProtocolAddress(
		nicID,
		protoAddr,
		stack.AddressProperties{},
	); err != nil {
		return nil, fmt.Errorf("AddProtocolAddress: %v", err)
	}

	/*
		These two are crucial.

		The packets arriving through WireGuard are things like:

		    10.77.0.2 -> 9.9.9.9
		    10.77.0.2 -> 1.1.1.1
		    10.77.0.2 -> 142.x.x.x

		9.9.9.9 obviously isn't an address belonging to our virtual NIC.

		Promiscuous + spoofing tell gVisor that this NIC is being used as
		a transparent gateway and that arbitrary destination/source IPs
		are legitimate.
	*/
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("SetPromiscuousMode: %v", err)
	}

	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("SetSpoofing: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
	})

	sack := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(
		tcp.ProtocolNumber,
		&sack,
	); err != nil {
		return nil, fmt.Errorf("enable TCP SACK: %v", err)
	}

	t.notifyHandle = ep.AddNotify(t)

	/*
		Install transparent TCP and UDP interception BEFORE traffic starts.
	*/
	installTCPForwarder(s)
	installUDPForwarder(s)

	t.events <- tun.EventUp

	return t, nil
}

func (t *netTun) File() *os.File {
	return nil
}

func (t *netTun) Name() (string, error) {
	return "userspace-netstack", nil
}

func (t *netTun) Events() <-chan tun.Event {
	return t.events
}

func (t *netTun) MTU() (int, error) {
	return t.mtu, nil
}

func (t *netTun) BatchSize() int {
	return 1
}

/*
Read():

gVisor -> WireGuard

This returns plaintext IP packets produced by gVisor.
WireGuard then encrypts them and sends them to the peer.
*/
func (t *netTun) Read(
	bufs [][]byte,
	sizes []int,
	offset int,
) (int, error) {
	var view *buffer.View

	select {
	case view = <-t.incomingPacket:
	case <-t.done:
		return 0, os.ErrClosed
	}

	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, errors.New("no receive buffer")
	}

	n, err := view.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}

	sizes[0] = n

	return 1, nil
}

/*
Write():

WireGuard -> gVisor

wireguard-go calls this after decrypting a transport packet.
The buffer contains a normal IPv4 packet.
*/
func (t *netTun) Write(
	bufs [][]byte,
	offset int,
) (int, error) {
	for _, b := range bufs {
		if len(b) <= offset {
			continue
		}

		packet := b[offset:]

		if len(packet) == 0 {
			continue
		}

		version := packet[0] >> 4

		if version != 4 {
			/*
				IPv4-only intentionally.

				We don't silently escape IPv6 outside the tunnel.
			*/
			continue
		}

		pkt := stack.NewPacketBuffer(
			stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(packet),
			},
		)

		t.ep.InjectInbound(
			header.IPv4ProtocolNumber,
			pkt,
		)
	}

	return len(bufs), nil
}

/*
WriteNotify is called by channel.Endpoint when gVisor has an outbound packet.

That packet needs to go back through WireGuard.
*/
func (t *netTun) WriteNotify() {
	for {
		pkt := t.ep.Read()
		if pkt == nil {
			return
		}

		view := pkt.ToView()
		pkt.DecRef()

		// Never block the gVisor stack: if WireGuard cannot keep up,
		// drop the packet and let TCP retransmit.
		select {
		case t.incomingPacket <- view:
		default:
			view.Release()
		}
	}
}

func (t *netTun) Close() error {
	t.closeOnce.Do(func() {
		if t.notifyHandle != nil {
			t.ep.RemoveNotify(t.notifyHandle)
		}

		t.stack.RemoveNIC(nicID)
		t.stack.Close()
		t.ep.Close()

		close(t.done)
		close(t.events)
	})

	return nil
}

/*
TCP FORWARDING

Example incoming packet:

	10.77.0.2:49231 -> 104.18.32.47:443

gVisor terminates the client's TCP connection.

We then create:

	ordinary Go TCP socket -> 104.18.32.47:443

Therefore the host (or container runtime) handles actual Internet egress.

No kernel forwarding or NAT is involved.
*/
func installTCPForwarder(s *stack.Stack) {
	fwd := tcp.NewForwarder(
		s,
		0,
		4096,
		func(r *tcp.ForwarderRequest) {
			id := r.ID()

			dstIP := tcpipAddressString(id.LocalAddress)

			dst := net.JoinHostPort(
				dstIP,
				strconv.Itoa(int(id.LocalPort)),
			)

			debugf("TCP new %s:%d -> %s",
				tcpipAddressString(id.RemoteAddress),
				id.RemotePort,
				dst,
			)

			if blockedDestination(net.ParseIP(dstIP)) {
				log.Printf("TCP %s blocked (private/local destination)", dst)
				r.Complete(true)
				return
			}

			go forwardTCP(r, dst)
		},
	)

	s.SetTransportProtocolHandler(
		tcp.ProtocolNumber,
		fwd.HandlePacket,
	)
}

// forwardTCP runs off the packet-processing path: a slow dial must never
// stall the gVisor stack for every other connection.
func forwardTCP(r *tcp.ForwarderRequest, dst string) {
	/*
		Dial Internet first.

		If destination cannot be reached, reset the client's
		connection instead of completing an unusable TCP handshake.
	*/
	outside, err := net.DialTimeout("tcp4", dst, 15*time.Second)
	if err != nil {
		log.Printf("TCP dial %s failed: %v", dst, err)
		r.Complete(true)
		return
	}

	var wq waiter.Queue

	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		log.Printf("TCP CreateEndpoint %s failed: %v", dst, tcpErr)

		outside.Close()
		r.Complete(true)
		return
	}

	r.Complete(false)

	inside := gonet.NewTCPConn(&wq, ep)

	relayTCP(inside, outside, dst)
}

func relayTCP(
	inside net.Conn,
	outside net.Conn,
	dst string,
) {
	defer inside.Close()
	defer outside.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	copyOne := func(dstConn, srcConn net.Conn) {
		defer wg.Done()

		_, _ = io.Copy(dstConn, srcConn)

		if c, ok := dstConn.(interface {
			CloseWrite() error
		}); ok {
			_ = c.CloseWrite()
		}
	}

	go copyOne(outside, inside)
	go copyOne(inside, outside)

	wg.Wait()

	debugf("TCP closed %s", dst)
}

/*
UDP FORWARDING

Each gVisor UDP flow gets one ordinary connected UDP socket.

Example:

	inner:
	    10.77.0.2:44000 -> 9.9.9.9:53

	outside:
	    container ephemeral -> 9.9.9.9:53

Responses are copied back into the gVisor endpoint.

gVisor then emits:

	9.9.9.9:53 -> 10.77.0.2:44000

which wireguard-go encrypts back to the peer.
*/
func installUDPForwarder(s *stack.Stack) {
	fwd := udp.NewForwarder(
		s,
		func(r *udp.ForwarderRequest) {
			id := r.ID()

			dstIP := tcpipAddressString(id.LocalAddress)

			dst := net.JoinHostPort(
				dstIP,
				strconv.Itoa(int(id.LocalPort)),
			)

			debugf("UDP new %s:%d -> %s",
				tcpipAddressString(id.RemoteAddress),
				id.RemotePort,
				dst,
			)

			if blockedDestination(net.ParseIP(dstIP)) {
				log.Printf("UDP %s blocked (private/local destination)", dst)
				return
			}

			var wq waiter.Queue

			ep, tcpErr := r.CreateEndpoint(&wq)
			if tcpErr != nil {
				log.Printf(
					"UDP CreateEndpoint %s failed: %v",
					dst,
					tcpErr,
				)
				return
			}

			inside := gonet.NewUDPConn(&wq, ep)

			outside, err := net.DialTimeout(
				"udp4",
				dst,
				10*time.Second,
			)
			if err != nil {
				log.Printf("UDP dial %s failed: %v", dst, err)
				inside.Close()
				return
			}

			go relayUDP(inside, outside, dst)
		},
	)

	s.SetTransportProtocolHandler(
		udp.ProtocolNumber,
		fwd.HandlePacket,
	)
}

func relayUDP(
	inside net.Conn,
	outside net.Conn,
	dst string,
) {
	defer inside.Close()
	defer outside.Close()

	done := make(chan struct{}, 2)

	copyPackets := func(
		dstConn net.Conn,
		srcConn net.Conn,
	) {
		defer func() {
			done <- struct{}{}
		}()

		buf := make([]byte, 65535)

		for {
			/*
				UDP association disappears after two minutes idle.
			*/
			_ = srcConn.SetReadDeadline(
				time.Now().Add(2 * time.Minute),
			)

			n, err := srcConn.Read(buf)

			if n > 0 {
				_, writeErr := dstConn.Write(buf[:n])
				if writeErr != nil {
					return
				}
			}

			if err != nil {
				return
			}
		}
	}

	go copyPackets(outside, inside)
	go copyPackets(inside, outside)

	<-done

	/*
		Closing either socket wakes the other goroutine.
	*/
	_ = inside.Close()
	_ = outside.Close()

	<-done

	debugf("UDP closed %s", dst)
}

func tcpipAddressString(a tcpip.Address) string {
	b := a.AsSlice()

	ip := net.IP(b)

	return ip.String()
}

func keyBase64ToHex(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}

	if len(raw) != 32 {
		return "", fmt.Errorf(
			"WireGuard key must decode to 32 bytes, got %d",
			len(raw),
		)
	}

	return hex.EncodeToString(raw), nil
}

func envInt(name string, fallback int) int {
	s := os.Getenv(name)

	if s == "" {
		return fallback
	}

	v, err := strconv.Atoi(s)
	if err != nil {
		log.Fatalf("%s=%q is not an integer", name, s)
	}

	return v
}

type config struct {
	ServerPrivateKey string // base64
	PeerPublicKey    string // base64
	Address          string // gateway's own address inside the tunnel
	PeerAddress      string // the single client address allowed
	Port             int
	MTU              int
}

// envAny returns the first non-empty environment variable among names.
func envAny(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}

	return ""
}

func envDefault(fallback string, names ...string) string {
	if v := envAny(names...); v != "" {
		return v
	}

	return fallback
}

func configFromEnv() config {
	required := func(names ...string) string {
		v := envAny(names...)
		if v == "" {
			log.Fatalf("%s is required", names[0])
		}

		return v
	}

	return config{
		ServerPrivateKey: required("SERVER_PRIVATE_KEY"),
		// PHONE_* are the original names and are still accepted.
		PeerPublicKey: required("PEER_PUBLIC_KEY", "PHONE_PUBLIC_KEY"),
		Address:       envDefault("10.77.0.1", "WG_ADDRESS"),
		PeerAddress:   envDefault("10.77.0.2", "PEER_ADDRESS", "PHONE_ADDRESS"),
		Port:          envInt("WG_PORT", 51820),
		MTU:           envInt("MTU", 1280),
	}
}

// start brings the gateway up and returns a function that shuts it down.
func start(cfg config, logLevel int) (func(), error) {
	serverPrivateHex, err := keyBase64ToHex(cfg.ServerPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("SERVER_PRIVATE_KEY: %w", err)
	}

	peerPublicHex, err := keyBase64ToHex(cfg.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("PEER_PUBLIC_KEY: %w", err)
	}

	tunDev, err := newNetTun(cfg.Address, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}

	dev := device.NewDevice(
		tunDev,
		conn.NewDefaultBind(),
		device.NewLogger(logLevel, "wg: "),
	)

	/*
		wireguard-go's IPC configuration protocol uses hex keys,
		not the base64 notation used by normal wg.conf files.
	*/
	ipc := fmt.Sprintf(
		"private_key=%s\n"+
			"listen_port=%d\n"+
			"public_key=%s\n"+
			"allowed_ip=%s/32\n",
		serverPrivateHex,
		cfg.Port,
		peerPublicHex,
		cfg.PeerAddress,
	)

	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, fmt.Errorf("WireGuard IpcSet: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("WireGuard Up: %w", err)
	}

	return func() {
		dev.Close()
		_ = tunDev.Close()
	}, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)

	cfg := configFromEnv()

	log.Printf("starting userspace WireGuard gateway %s", version)
	log.Printf(
		"address=%s peer=%s port=%d mtu=%d allow_private=%v",
		cfg.Address,
		cfg.PeerAddress,
		cfg.Port,
		cfg.MTU,
		allowPrivate,
	)

	stop, err := start(cfg, device.LogLevelError)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("READY: WireGuard UDP :%d, TCP+UDP userspace forwarding", cfg.Port)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("shutting down")
	stop()
}
