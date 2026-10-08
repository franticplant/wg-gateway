package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func genKey(t *testing.T) (priv, pub [32]byte) {
	t.Helper()

	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}

	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64

	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}

	copy(pub[:], p)

	return priv, pub
}

// hostIPv4 returns a non-loopback IPv4 address of this machine. Tunnel
// traffic to 127.0.0.1 never leaves the client's own stack, so the test
// servers listen on a real interface address instead.
func hostIPv4(t *testing.T) string {
	t.Helper()

	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			return n.IP.String()
		}
	}

	t.Skip("no non-loopback IPv4 address available")

	return ""
}

func b64(k [32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }

// freeUDPPort asks the kernel for an unused UDP port on loopback.
func freeUDPPort(t *testing.T) int {
	t.Helper()

	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	return c.LocalAddr().(*net.UDPAddr).Port
}

// newTunnel starts a gateway plus an in-process WireGuard client and returns
// the client's network stack.
func newTunnel(t *testing.T) *netstack.Net {
	t.Helper()

	serverPriv, serverPub := genKey(t)
	clientPriv, clientPub := genKey(t)
	port := freeUDPPort(t)

	stop, err := start(config{
		ServerPrivateKey: b64(serverPriv),
		PeerPublicKey:    b64(clientPub),
		Address:          "10.77.9.1",
		PeerAddress:      "10.77.9.2",
		Port:             port,
		MTU:              1280,
	}, device.LogLevelError)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.77.9.2")},
		nil,
		1280,
	)
	if err != nil {
		t.Fatal(err)
	}

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "client: "))
	t.Cleanup(dev.Close)

	err = dev.IpcSet(fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1\n",
		hex.EncodeToString(clientPriv[:]),
		hex.EncodeToString(serverPub[:]),
		port,
	))
	if err != nil {
		t.Fatal(err)
	}

	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}

	return tnet
}

func TestTCPAndUDPThroughTunnel(t *testing.T) {
	// The test targets live on a private address, which is normally blocked.
	allowPrivate = true
	t.Cleanup(func() { allowPrivate = false })

	host := hostIPv4(t)

	web := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "hello through wireguard")
	}))
	l, err := net.Listen("tcp4", host+":0")
	if err != nil {
		t.Fatal(err)
	}
	web.Listener = l
	web.Start()
	defer web.Close()

	echo, err := net.ListenPacket("udp4", host+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buf[:n], addr)
		}
	}()

	tnet := newTunnel(t)

	t.Run("tcp", func(t *testing.T) {
		c := &http.Client{
			Transport: &http.Transport{DialContext: tnet.DialContext},
			Timeout:   15 * time.Second,
		}

		resp, err := c.Get(web.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "hello through wireguard" {
			t.Fatalf("unexpected body %q", body)
		}
	})

	t.Run("udp", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		c, err := tnet.DialContext(ctx, "udp", echo.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()

		_ = c.SetDeadline(time.Now().Add(10 * time.Second))

		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}

		buf := make([]byte, 16)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}

		if string(buf[:n]) != "ping" {
			t.Fatalf("unexpected echo %q", buf[:n])
		}
	})
}

func TestPrivateDestinationsBlockedByDefault(t *testing.T) {
	tnet := newTunnel(t)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// 192.168.0.0/16 is private, so the gateway must refuse the connection.
	if c, err := tnet.DialContext(ctx, "tcp", "192.168.77.77:80"); err == nil {
		c.Close()
		t.Fatal("connection to a private address should have been refused")
	}
}

func TestBlockedDestination(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1":       true,
		"10.0.0.5":        true,
		"192.168.1.1":     true,
		"172.16.0.1":      true,
		"169.254.169.254": true,
		"100.100.1.1":     true,
		"224.0.0.1":       true,
		"1.1.1.1":         false,
		"9.9.9.9":         false,
	} {
		if got := blockedDestination(net.ParseIP(ip)); got != want {
			t.Errorf("blockedDestination(%s) = %v, want %v", ip, got, want)
		}
	}
}
