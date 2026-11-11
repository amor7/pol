# pol

**[فارسی](README.fa.md)**

*pol* (پل, "bridge") forwards TCP and UDP ports from a server in Iran to a server abroad through an encrypted tunnel, with **fifteen tunnel modes** to choose from per port and an **auto** mode that chooses for you. Users connect to the Iran server; their connections arrive at your server abroad as if they had connected to it directly.

```
              ┌──────────── Iran ────────────┐                     ┌────────── abroad ──────────┐
 users ──────►│ relay  :2088  :8443  :443/udp│═══ any of 15 modes ═►│ server ──► 127.0.0.1:2088  │
              └──────────────────────────────┘                     │            127.0.0.1:443   │
                                                                   └────────────────────────────┘
```

- **One command to install**, one command per port (`pol add 2088`), or type `pol` for a menu.
- **Fifteen modes, each a different kind of road**: when one is slow or blocked on your path, another usually is not. `pol speedtest` measures them on your own servers; `auto` keeps using the best one that works.
- **TCP and UDP.** VLESS, VMess, Trojan, Reality, WebSocket, gRPC, SSH; with UDP ports also Hysteria2, TUIC, WireGuard, KCP.
- **Changes apply at once.** Add, remove or switch a port's mode and its users reconnect through the new road within a second or two; other ports are not touched.
- **Pinned and authenticated.** The relay trusts only your server's certificate and proves itself with a secret. Anyone else sees an ordinary nginx error page - or, with camo, the real website.

## Install

You need two Linux servers (amd64 or arm64) and root on both.

**1. On the server abroad** (where x-ui or your other services run):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/amor7/pol/main/install.sh) server
```

It picks a free tunnel port (443 if free, otherwise 8443, …), starts the service, lists the ports to open in your provider's firewall, and prints one line to run on the Iran server.

**2. On the server in Iran**, run the line it printed:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/amor7/pol/main/install.sh) relay pol1_eyJzIjoi... --ports 2088
```

That is all: users now connect to the Iran server's IP on port 2088 and reach port 2088 abroad. For x-ui and similar panels, keep the inbound as it is and put the Iran server's address in the client configs; the port stays the same.

Run the installer again later, without arguments, to update.

## Tunnel modes

Every port has its own mode; change it any time with `pol mode <port> <mode>`. `pol modes` prints this list on the server.

**Traffic** is what a mode adds on top of your users' own data, in three parts, all measured on a clean link (`TestOverhead`, `TestCostProbe`):

- **on transfers**: per byte moved; what a big download costs.
- **per connection**: to open one; what web pages and apps cost, since they open many short connections. That is where tls and split cost the most, and obfs, mux and ssh the least.
- **a day idle**: keeping the mode ready with nobody on it. A mode is kept ready only while a port uses it.

Packet headers (a few % for every mode) and resends on a lossy path come on top.

### Fast

| Mode | How it travels | Good for | Traffic |
|---|---|---|---|
| **auto** | ranks the other modes and uses the best one that works; switches at once when one fails | not having to watch it | ~100 MB a day for its checks + the chosen mode's |
| **tls** *(default)* | a TLS connection per user connection, from a pool kept ready | **high-speed download, high-speed upload** | +1% · +3.5 kB per connection · 14 MB/day idle |
| **split** | each user connection spread over 4 TLS connections at once, reassembled in order | **high-speed download and upload**, even for one big file; beats per-connection throttling | +1% · **+14 kB per connection** · 15 MB/day idle |

### Stealth

| Mode | How it travels | Good for | Traffic |
|---|---|---|---|
| **obfs** | TCP carrying an AES stream, no TLS handshake, random padding | **high-speed download**; looks like noise from the first byte | under +1% · +0.2 kB per connection · 2.5 MB/day idle |
| **camo** | borrows a real website's TLS (Chrome's handshake, the site's real certificate); anyone without the secret gets the real site | **hardest to detect**, strongest against active probing | +1% · +4 kB or more per connection · 7 MB/day idle |
| **mux** | everything as streams inside a few HTTP/2 connections | one long HTTPS session from outside | +1% · +0.2 kB per connection · 24 MB/day idle |
| **ssh** | one real SSH connection, a channel per user connection | looks like server administration | +1% · +0.4 kB per connection · 1.5 MB/day idle |

### CDN

| Mode | How it travels | Good for | Traffic |
|---|---|---|---|
| **ws** | a WebSocket per user connection | going **through Cloudflare** when the server's IP is blocked (`pol cdn`) | +1% · +4 kB per connection · 9 MB/day idle |
| **xhttp** | plain HTTP: one long GET down, numbered POSTs up | through CDNs and proxies that carry **only ordinary requests**; looks like web browsing | +1% · +0.5 kB per connection · 2 MB/day idle |

### UDP

| Mode | How it travels | Good for | Traffic |
|---|---|---|---|
| **quic** | streams of one QUIC connection | **lossy networks, low ping** | +3% · +0.7 kB per connection · 5 MB/day idle |
| **kcp** | KCP over UDP, lost packets rebuilt from spare data (FEC) | **gaming / lowest ping** on lossy paths | **+45–75%** · +6 kB per connection · 8 MB/day idle |
| **hop** | kcp, changing UDP port every 30 seconds | gaming where **one UDP port gets slowed down** after a while | **+45–75%** · ~+6 kB per connection · ~8 MB/day idle |
| **faketcp** | kcp's packets dressed as TCP segments | gaming where **UDP as a whole is throttled** | **+40–70%** · ~+6 kB per connection · ~8 MB/day idle |

### Special

| Mode | How it travels | Good for | Traffic |
|---|---|---|---|
| **reverse** | the server connects to the relay, not the other way round | when connections **from Iran out** are cut but ones coming in are not | +1% · +0.2 kB per connection · ~15 MB/day idle |
| **dns** | data inside DNS lookups, through any resolver | **emergency only**: when nothing but DNS gets out. Slow: tens to a few hundred kbit/s | **+130% down, +550% up** · ~15 MB/day idle |
| **direct** | plain TCP/UDP straight to the port abroad, no pol in between | the fastest, nothing added; the service's own encryption is all there is | 0% |

### Which one?

1. Run `pol speedtest` on the relay. It measures every mode through your real path, four connections at a time as a phone would, ranks them and shows each one's traffic cost.
2. Put the port on the winner (`pol mode 2088 mux`), or on `auto` to let pol keep choosing. For ordinary use (web, apps: many short connections) prefer **mux or obfs**: about as fast, and far cheaper per connection than tls or split. Keep **split** for big downloads.
3. For games, try quic first; kcp, hop and faketcp give lower ping on bad paths, but cost much more traffic.
4. Keep a ws or xhttp port through a CDN ready for the day the server's IP is blocked.

## Ports to open

Everything except the extra UDP/raw modes uses the **one tunnel port** (say 8443). The others count from it:

| Port (tunnel port 8443) | Protocol | Modes |
|---|---|---|
| 8443 | TCP | tls, split, mux, obfs, camo, ws, xhttp, ssh |
| 8443 | UDP | quic |
| 8444 | UDP | kcp |
| 8445 | TCP (raw) | faketcp |
| 8453–8472 | UDP | hop |
| 53 | UDP | dns (only if set up) |

`pol setup server` and `pol update` open these in **ufw** when it is active. If your provider has a firewall in its web panel, open them there yourself; `pol status` on the server lists them. On the relay, open the ports you forward (and the reverse port if you use it).

## Setting up the special modes

### auto

```bash
pol mode 2088 auto                 # choose among every mode set up here
pol mode 2088 auto:split,tls,ws    # or only among these, in this order of preference
```

auto checks every candidate every 5 minutes and measures their speed every 3 hours (about 100 MB a day in all). New connections go to the best one that answers. A mode that fails is set aside for half an hour and the connection is tried on the next one at once. `pol status` shows its ranking.

### camo

Works out of the box, borrowing `www.microsoft.com`. To borrow another site, set the same one on **both** servers:

```bash
pol camo www.speedtest.net
```

Pick a large site that serves TLS 1.3 and is not blocked in Iran. The relay never connects to the site itself, only the server does; the site's name is just what anyone watching the Iran side sees.

### CDN for ws and xhttp (when the server's IP is blocked)

1. Point a domain on Cloudflare (proxied, orange cloud) at the server and set SSL/TLS to **Full**.
2. The server's tunnel port must be one Cloudflare proxies: 443, 2053, 2083, 2087, 2096 or 8443.
3. On the relay:

```bash
pol cdn t.yourdomain.com --ip 172.66.172.174    # --ip: a Cloudflare address that works from Iran
pol mode 2088 xhttp                              # or ws
```

### reverse

On the relay `pol reverse`; it prints `pol link pol1r_...` to run on the server. Then `pol mode 2088 reverse` on the relay.

### dns (emergency)

1. At your domain's DNS host: an A record `ns.yourdomain.com` → the server's IP, and an NS record `t.yourdomain.com` → `ns.yourdomain.com`.
2. On the server: `pol dns t.yourdomain.com` (needs UDP 53 free).
3. On the relay: `pol dns t.yourdomain.com --resolver 8.8.8.8`. Any resolver the relay can reach works, an Iranian one too.
4. `pol speedtest --mode dns`, then `pol mode 2088 dns` while nothing else gets out.

### faketcp

Needs Linux and `iptables` on both servers (both are standard). pol adds and removes its iptables rule itself.

### Middle hop (`pol via`)

When the main server's IP is blocked from Iran, put a second server with a clean IP in between:

```
Iran relay ══ any mode ══► middle server ══ tls (or another mode) ══► main server ──► x-ui
```

On the middle server, set up pol (`pol setup server`) and point it at the main server with the main server's token:

```bash
pol via pol1_<main server's token> [--mode tls]
```

Give the relay the **middle server's** token. Nothing else changes: ports, x-ui and client configs stay as they are.

## Commands

Type **`pol`** on either server for a menu of everything, by number. Or use the commands directly.

On the **relay** (Iran):

| Command | What it does |
|---|---|
| `pol add 2088` | forward port 2088 to port 2088 on the server |
| `pol add 2088:443` | forward port 2088 here to port 443 on the server |
| `pol add 2080-2085` · `pol add 2088 8443` | a range; several at once |
| `pol add 443/udp` · `pol add 2096 --both` | a UDP port; TCP and UDP together |
| `pol add 2088 --mode split` | choose the mode (default `tls`) |
| `pol mode 2088 quic` | change the mode of forwarded ports, at once |
| `pol del 2088` | stop forwarding (`2088/udp` for just UDP) |
| `pol list` | forwarded ports with live connections and traffic |
| `pol modes` | every mode, what it is for and what it costs |
| `pol speedtest [MB] [--mode M]` | speed of every mode (or one), ranked, with traffic cost |
| `pol ping` | round-trip time through the tunnel |
| `pol cdn <domain> [--ip A]` · `pol cdn off` | send ws and xhttp through a CDN |
| `pol camo <site>` | the website camo borrows (same on both servers) |
| `pol reverse` · `pol reverse off` | set up / remove reverse mode |
| `pol dns <domain> [--resolver A]` · `pol dns off` | set up dns mode |

On the **server** (abroad):

| Command | What it does |
|---|---|
| `pol token` · `pol token --new` | print the join token; replace the secret |
| `pol link <token>` · `pol unlink <addr>` | reverse mode: keep connections to a relay / stop |
| `pol via <token> [--mode M]` · `pol via off` | be a middle hop to another server |
| `pol camo <site>` · `pol dns <domain>` | the server's side of camo and dns |

On **both**: `pol status`, `pol logs [-f] [-e]`, `pol restart` · `stop` · `start`, `pol tune` (BBR), `pol update`, `pol uninstall`.

## Configuration

Everything lives in `/etc/pol/config.json` (root only). The commands edit it for you; edits by hand are picked up within two seconds on the relay.

- `relay.conns`: HTTP/2 connections for mux (default 2). `relay.split_conns`: connections split spreads each user over (default 4, up to 16).
- `relay.sni` / `server.sni`: the server name sent in TLS handshakes (default `example.com`). Nothing checks it, but Iran drops TLS handshakes without one.
- `server.any_target`: by default the server only forwards to its own ports (`127.0.0.1`); `true` lets `pol add 2088:10.0.0.5:443` reach other machines.
- `server.no_quic`: stop listening for quic.
- `extra_ports` (both): move the kcp, faketcp and hop ports (`kcp`, `faketcp`, `hop_from`, `hop_to`), the same on both servers.

Several Iran servers can use the same token at once.

## Installing without GitHub

If the Iran server cannot reach GitHub, download `pol-linux-amd64` from the [releases page](https://github.com/amor7/pol/releases) elsewhere, copy it over, and run:

```bash
install -m 755 pol-linux-amd64 /usr/local/bin/pol && pol setup relay pol1_... --ports 2088
```

Later updates the same way: `pol update --file pol-linux-amd64`.

## How it works

Whatever the mode, a stream ends the same way on the server: the relay names the target and the secret, the server checks them (its own ports only, unless `any_target`), connects, answers one status byte, and copies both ways. The modes differ only in the road:

- **tls / split**: TLS 1.3 with ALPN `pol1`, the server's certificate pinned by fingerprint. split numbers 16 kB chunks, sends each on whichever of its connections is free, and the other side reorders them.
- **mux**: HTTP/2, a `POST` per connection; each stream has its own 4 MB window and the connection 256 MB, so one user who stops reading only stops their own stream.
- **obfs**: 32 random bytes, then AES-256-CTR keyed from the secret and those bytes, with a timestamp and random padding; replayed recordings are ignored.
- **camo**: the relay sends a Chrome ClientHello naming the borrowed site; the server passes the handshake to the real site and back, so the relay gets the site's real certificate. The relay's next record is AES-GCM sealed with keys from the secret and the handshake's server random. The first record that opens with them switches the connection over; until then, everything goes to the real site.
- **ws / xhttp**: an HTTP/1.1 WebSocket upgrade, or a GET plus numbered POSTs, on the tunnel port, with keepalives so CDNs keep them open.
- **ssh**: a real SSH-2 handshake on the tunnel port, with the server's host key pinned through its certificate, and a channel per connection.
- **quic**: QUIC (TLS 1.3 inside) on the tunnel port's number over UDP, a stream per connection.
- **kcp / hop / faketcp / dns**: KCP (AES-encrypted, with FEC except dns) carrying an smux session, a stream per connection. The packets travel over plain UDP, over UDP that changes destination port every 30 seconds, as TCP segments on a raw socket (after a real handshake, with resets suppressed in iptables' raw table), or inside DNS queries and answers.
- **reverse**: the server dials the relay's reverse port (the relay's certificate pinned), proves the secret, and leaves connections waiting for users.

UDP datagrams travel as length-prefixed frames on a stream per client, in any mode. Probes see nginx: a 400 for plain HTTP, a 404 for HTTPS without the secret, silence for obfs, and the real site for camo.

## Building

```bash
go test ./...                       # every mode end to end; faketcp needs root on Linux
POL_OVERHEAD=1 go test -run TestOverhead -v ./internal/   # the traffic figures above
CGO_ENABLED=0 GOOS=linux go build -o pol .
```

Dependencies outside Go's standard library: [quic-go](https://github.com/quic-go/quic-go) (quic), [utls](https://github.com/refraction-networking/utls) (camo's Chrome handshake), [kcp-go](https://github.com/xtaci/kcp-go) and [smux](https://github.com/xtaci/smux) (kcp, hop, faketcp, dns), [x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh) (ssh).

## License

MIT
