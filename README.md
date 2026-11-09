# pol

**[فارسی](README.fa.md)**

*pol* (پل, "bridge") forwards TCP and UDP ports from one server to another through an **encrypted tunnel**, with **eight tunnel modes** to choose from per port. Users connect to a server in Iran; their connections arrive at your server abroad as if they had connected to it directly.

```
              ┌──────────── Iran ────────────┐                    ┌────────── abroad ──────────┐
 users ──────►│ relay  :2088  :8443  :443/udp│═══ tls / split ═══►│ server ──► 127.0.0.1:2088  │
              └──────────────────────────────┘    quic / mux …    │            127.0.0.1:443   │
                                                                  └────────────────────────────┘
```

- **One command to install**, one command per port: `pol add 2088`, `pol del 2088` - or type `pol` for a menu.
- **Eight modes, each a different kind of road**, so when one is slow or blocked on your path another may not be. `pol speedtest` measures them all on your own servers and ranks them.
- **TCP and UDP.** VLESS, VMess, Trojan, Reality, WebSocket, gRPC, SSH - and with UDP ports also Hysteria2, TUIC, WireGuard and KCP.
- **Pinned and authenticated.** The relay trusts only your server's certificate and proves itself with a secret. Anyone else who connects gets an ordinary nginx error page - or, on obfs, nothing at all.
- **Sturdy.** One stuck user cannot hold up the others; broken connections are noticed and redialled; a port something else holds is retried until it is free.

## Install

You need two Linux servers (amd64 or arm64) and root on both.

**1. On the server abroad** (where x-ui or your other services run):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/amor7/pol/main/install.sh) server
```

It picks a free tunnel port (443 if nothing uses it, otherwise 8443, …), starts the service, and prints one line to run on the Iran server.

**2. On the server in Iran**, run the line it printed. It looks like this:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/amor7/pol/main/install.sh) relay pol1_eyJzIjoi... --ports 2088
```

That is all. Users now connect to the Iran server's IP on port 2088 and reach port 2088 on the server abroad.

For x-ui and similar panels: keep the inbound as it is and, in the client config, replace the abroad server's address with the Iran server's address. The port stays the same.

Without arguments the installer asks which server it is on. Run it again later, without arguments, to update.

## Tunnel modes

Each port picks its own mode; change it any time with `pol mode <port> <mode>`.

| Mode | How it travels | Good for |
|---|---|---|
| **tls** *(default)* | a TLS connection per user connection, from a pool kept ready | the usual choice: encrypted and fast |
| **split** | each user connection spread over 4 TLS connections at once, reassembled in order | paths that throttle every connection: even one big download gets several connections' speed |
| **quic** | streams of one QUIC connection over UDP | lossy paths - a lost packet holds up only its own stream |
| **mux** | every connection a stream inside a few HTTP/2 connections | the most discreet: from outside, one long HTTPS session |
| **obfs** | TCP carrying an AES stream, no TLS handshake, random padding | when TLS to foreign servers is singled out: looks like noise from the first byte |
| **ws** | a WebSocket per connection, as a web page would open | going through **Cloudflare** when the server's IP is blocked (`pol cdn`) |
| **reverse** | the **server connects to the relay** and keeps connections waiting there | when connections from Iran out are cut but ones coming in are not (`pol reverse`) |
| **direct** | plain TCP/UDP straight to the port abroad, no pol in between | the fastest; the service's own encryption is all there is |

All modes but reverse and direct share the server's one tunnel port (TCP, and UDP for quic). The first bytes of a connection tell the server which mode it is.

### Which one?

Run `pol speedtest` on the relay. It measures every mode through your real path, four connections at a time as a phone would, and ranks them:

```
   MODE              DOWNLOAD           UPLOAD
   tls            118.2 Mbit/s      41.6 Mbit/s
   split          164.9 Mbit/s      44.0 Mbit/s
   quic            92.3 Mbit/s      38.1 Mbit/s
   mux              9.4 Mbit/s       8.8 Mbit/s
   ...
   ✓ fastest here: split (164.9 Mbit/s down, 44.0 Mbit/s up)
```

*(numbers are an example; yours depend on your servers and path)*

### UDP ports

```bash
pol add 443/udp --mode quic        # a UDP port (Hysteria2, TUIC, WireGuard, KCP ...)
pol add 2096 --both                # TCP and UDP on the same port
```

UDP datagrams travel framed inside whatever mode the port uses; in direct mode they go as plain UDP.

### Reverse mode

On the relay:

```bash
pol reverse
```

It opens a port for the server to connect to and prints `pol link pol1r_...` - run that on the server. Then `pol mode 2088 reverse` on the relay. `pol reverse off` and `pol unlink` undo it.

### Cloudflare for ws mode

Point a domain on Cloudflare (proxied, orange cloud) at the server, set SSL/TLS to **Full**, then on the relay:

```bash
pol cdn my.domain.com
pol mode 2088 ws
```

The server's tunnel port must be one Cloudflare proxies: 443, 2053, 2083, 2087, 2096 or 8443.

## Commands

Type **`pol`** on either server for a menu of everything below, by number:

```
   pol v1.3.0  relay · running

    1) Status
    2) Add ports
    3) Remove ports
    4) List ports
    5) Change the tunnel mode of ports
    6) Speed test (every mode, ranked)
    7) Ping through the tunnel
    8) Reverse mode: set up (prints a line for the server)
    9) CDN for ws mode (Cloudflare)
   10) Logs (live - Ctrl+C to stop)
   ...
```

Or use the commands directly.

On the **relay** (Iran):

| Command | What it does |
|---|---|
| `pol add 2088` | forward port 2088 to port 2088 on the server |
| `pol add 2088:443` | forward port 2088 here to port 443 on the server |
| `pol add 2080-2085` | forward a range, each port to the same port |
| `pol add 443/udp` · `pol add 2096 --both` | a UDP port; TCP and UDP together |
| `pol add 2088 --mode split` | choose the mode (default `tls`) |
| `pol mode 2088 quic` | change the mode of ports already forwarded |
| `pol del 2088` | stop forwarding (`2088/udp` for just UDP) |
| `pol list` | the forwarded ports, with live connections and traffic |
| `pol speedtest [MB] [--mode M]` | speed of every mode (or one), ranked |
| `pol ping` | round-trip time through the tunnel |
| `pol reverse` · `pol reverse off` | set up / remove reverse mode |
| `pol cdn <domain>` · `pol cdn off` | send ws mode through Cloudflare |

On the **server** (abroad):

| Command | What it does |
|---|---|
| `pol token` | print the join token and the install line again |
| `pol token --new` | replace the secret; relays need the new token |
| `pol link <token>` · `pol unlink <addr>` | keep reverse connections to a relay / stop |

On **both**:

| Command | What it does |
|---|---|
| `pol status` | every mode's state, the ports, traffic |
| `pol logs [-f] [-e]` | service logs (`-f` follow, `-e` problems only) |
| `pol restart` · `pol stop` · `pol start` | control the service |
| `pol tune` | turn on BBR and larger TCP buffers (recommended on both) |
| `pol update` | install the latest release, checksum verified |
| `pol uninstall` | remove pol |

Ports added or removed take effect immediately, without dropping the other ports' users. ufw rules follow them when ufw is active. If your provider has a firewall in its web panel, open the ports there yourself: on the server the tunnel port for **TCP and UDP**; on the relay the forwarded ports (and the reverse port if you use it).

## Configuration

Everything lives in `/etc/pol/config.json` (root only). The commands edit it for you; edits by hand are picked up within two seconds on the relay.

- `relay.conns` - HTTP/2 connections for mux mode (default 2).
- `relay.split_conns` - connections split mode spreads each user over (default 4).
- `relay.sni` / `server.sni` - the server name the relay announces in TLS handshakes (default `example.com`). Nothing checks it, but Iran drops TLS handshakes that have none.
- `server.any_target` - by default the server only forwards to its own ports (`127.0.0.1`). Set to `true` to let `pol add 2088:10.0.0.5:443` reach other machines.
- `server.no_quic` - stop listening for quic mode on UDP.

Several Iran servers can use the same token at once.

## Installing without GitHub

If the Iran server cannot reach GitHub, download `pol-linux-amd64` from the [releases page](https://github.com/amor7/pol/releases) on a computer that can, copy it over, and run:

```bash
install -m 755 pol-linux-amd64 /usr/local/bin/pol && pol setup relay pol1_... --ports 2088
```

Later updates the same way: `pol update --file pol-linux-amd64`.

## How it works

Whatever the mode, a stream ends the same way on the server: the relay names the target, the server checks it (its own ports only, unless `any_target`) and the secret, connects, answers one status byte, and copies both ways. The modes differ only in the road:

- **tls / split** - TLS 1.3 with ALPN `pol1`, the server's certificate pinned by fingerprint. split numbers 16 kB chunks and sends each on whichever of its connections is free; the other side reorders them.
- **mux** - HTTP/2 over TLS, a `POST` per connection; each stream has its own 4 MB window and the connection 256 MB, so a user who stops reading only stops their own stream.
- **quic** - QUIC (TLS 1.3 inside) on the tunnel port's number over UDP, a stream per connection.
- **obfs** - 32 random bytes, then AES-256-CTR keyed from the secret and those bytes, with a timestamp and random padding; a replayed recording is ignored.
- **ws** - an HTTP/1.1 WebSocket upgrade on the tunnel port, pinging every 30 seconds so CDNs keep it open.
- **reverse** - the server dials the relay's reverse port (the relay's own certificate pinned), proves the secret, and leaves connections waiting; the relay uses one per user and the server replaces it.

UDP datagrams travel as length-prefixed frames on a stream per client. Probes see nginx: a 400 for plain HTTP, a 404 for HTTPS without the secret, silence for obfs without it.

## Building

```bash
go test ./...
CGO_ENABLED=0 GOOS=linux go build -o pol .
```

The only dependency outside Go's standard library is [quic-go](https://github.com/quic-go/quic-go), for quic mode.

## License

MIT
