# wg-gateway

A tiny WireGuard server that runs **entirely in userspace**: no `/dev/net/tun`,
no kernel WireGuard module, no `NET_ADMIN`, no `ip_forward`, no NAT rules.
It works as an unprivileged container, including rootless Podman.

Decrypted tunnel traffic is terminated by an in-process network stack
([gVisor netstack](https://gvisor.dev/)). Every TCP connection and UDP flow
is re-originated as an ordinary socket from the host, so the host's normal
networking handles Internet egress.

```
phone / client ──WireGuard──▶ wg-gateway ──ordinary sockets──▶ Internet
                              (wireguard-go + gVisor netstack)
```

## Quick start

Generate keys (needs `wireguard-tools`):

```sh
wg genkey | tee server.key | wg pubkey > server.pub
wg genkey | tee peer.key   | wg pubkey > peer.pub
```

Create `server.env` (see [`server.env.example`](server.env.example)):

```sh
SERVER_PRIVATE_KEY=<contents of server.key>
PEER_PUBLIC_KEY=<contents of peer.pub>
```

Run:

```sh
podman run -d --name wg-gateway \
  -p 51820:51820/udp \
  --env-file server.env \
  ghcr.io/franticplant/wg-gateway:latest
```

(`docker` works the same way.)

Client configuration:

```ini
[Interface]
PrivateKey = <contents of peer.key>
Address    = 10.77.0.2/32
DNS        = 1.1.1.1
MTU        = 1280

[Peer]
PublicKey           = <contents of server.pub>
Endpoint            = <host>:51820
AllowedIPs          = 0.0.0.0/0
PersistentKeepalive = 25
```

Open `51820/udp` in your host firewall, restricted to the client if you can.

## Configuration

| Variable             | Default     | Meaning                                                  |
| -------------------- | ----------- | -------------------------------------------------------- |
| `SERVER_PRIVATE_KEY` | required    | Server private key (base64, as printed by `wg genkey`)   |
| `PEER_PUBLIC_KEY`    | required    | The client's public key (`PHONE_PUBLIC_KEY` also works)  |
| `WG_ADDRESS`         | `10.77.0.1` | Gateway address inside the tunnel                        |
| `PEER_ADDRESS`       | `10.77.0.2` | The one address the client may use (`PHONE_ADDRESS` too) |
| `WG_PORT`            | `51820`     | UDP listen port                                          |
| `MTU`                | `1280`      | Tunnel MTU                                               |
| `VERBOSE`            | unset       | Log every proxied TCP/UDP connection                     |
| `ALLOW_PRIVATE`      | unset       | Let the client reach private/loopback/LAN destinations   |

## Security notes

- **One peer, one address.** The gateway accepts a single client.
- **Private destinations are blocked by default.** Because connections are
  made from the host's network namespace, an unrestricted client could reach
  the host's loopback, LAN, Tailscale (`100.64.0.0/10`), link-local and cloud
  metadata addresses. These are refused unless you set `ALLOW_PRIVATE=1`. This
  also means DNS must use a public resolver such as `1.1.1.1`.
- **IPv4 only.** IPv6 packets are dropped rather than leaking outside the
  tunnel. ICMP (ping) is not supported.
- The container image is `FROM scratch`, runs as UID 65532, and has no shell.

## Building

```sh
go build -o wg-gateway .
go test -race ./...        # end-to-end test: in-process WireGuard client
podman build -t wg-gateway .
```

Releases are built from `v*` tags: multi-arch images (`linux/amd64`,
`linux/arm64`) on GHCR with SBOM and provenance attestation, plus static
binaries and checksums attached to the GitHub release.

## Verifying releases

Release images and binaries carry
[GitHub build provenance attestations](https://docs.github.com/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds),
signed by the release workflow. Check that what you run was built from this
repository by that workflow:

```sh
# container image
gh attestation verify oci://ghcr.io/franticplant/wg-gateway:latest \
  --repo franticplant/wg-gateway

# downloaded binary
gh attestation verify wg-gateway-linux-amd64 --repo franticplant/wg-gateway
```

## License

MIT
