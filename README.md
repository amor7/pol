# pol

**[فارسی](README.fa.md)**

*pol* (پل, "bridge") forwards TCP ports from one server to another through **one encrypted tunnel**. Users connect to a server in Iran; their connections arrive at your server abroad as if they had connected to it directly.

```
              ┌──────────── Iran ────────────┐                 ┌────────── abroad ──────────┐
 users ──────►│ relay  :2088  :8443  :2096 … │══ one TLS ═════►│ server ──► 127.0.0.1:2088  │
              └──────────────────────────────┘   connection    │            127.0.0.1:443   │
                                                 (HTTP/2)      └────────────────────────────┘
```

- **One command to install**, one command per port: `pol add 2088`, `pol del 2088`.
- **One connection between the servers.** Every user connection is a stream inside one HTTPS connection (a few, for speed). From outside it is an ordinary HTTPS client talking to a web server. What users connect to stays inside.
- **Pinned and authenticated.** The relay trusts only your server's certificate (by fingerprint) and proves itself with a secret. Anyone else who connects gets an ordinary nginx "404 Not Found".
- **Sturdy.** Each connection has its own flow-control window, so one stuck user cannot hold up the others. Broken tunnel connections are noticed within seconds and redialled. A port that something else holds is retried until it is free.
- **Small.** One static binary built from Go's standard library alone - no dependencies.

TCP only. Anything that runs over TCP works: VLESS / VMess / Trojan over TCP, WebSocket, gRPC or HTTPUpgrade, **Reality**, SSH, game servers on TCP, web panels. UDP-based protocols (Hysteria2, TUIC, KCP, QUIC, WireGuard) do not.

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

Each port picks how its connections travel, and different ports can use different modes:

| Mode | How | When |
|---|---|---|
| **tls** (default) | every user connection gets its own TLS connection to the server, from a pool kept ready so nobody waits for the handshake | the usual choice: encrypted, and fast on lossy paths and on networks that slow each connection down |
| **mux** | every user connection is a stream inside a few HTTP/2 connections | the most discreet: from outside it is one HTTPS session; slower when the path loses packets |
| **direct** | plain TCP straight to the port on the server, no pol in between | the fastest; nothing is added, so the service's own encryption (Reality, TLS) is all there is, and the port must be reachable from the relay |

`pol speedtest` measures tls and mux side by side, four connections at a time as a phone would open, so you can see which suits your path. Both modes share the one tunnel port on the server; direct uses the service's own port.

```bash
pol add 2088 --mode tls      # new ports are tls unless you say otherwise
pol mode 2088 mux            # change a port's mode; open connections finish as they are
```

## Commands

Type **`pol`** on either server for a menu of everything below, by number:

```
   pol v1.2.0  relay · running

    1) Status
    2) Add ports
    3) Remove ports
    4) List ports
    5) Change the tunnel mode of ports
    6) Ping through the tunnel
    7) Speed test (compares the modes)
    8) Logs (live - Ctrl+C to stop)
    9) Restart
   10) Stop
   11) Speed up the network (BBR)
   12) Update pol
   13) Set up again
   14) Uninstall
    0) Exit
```

Or use the commands directly:

On the **relay** (Iran):

| Command | What it does |
|---|---|
| `pol add 2088` | forward port 2088 to port 2088 on the server |
| `pol add 2088:443` | forward port 2088 here to port 443 on the server |
| `pol add 2080-2085` | forward a range, each port to the same port |
| `pol add 2088 8443 2096` | several at once (commas work too) |
| `pol add 2088 --mode mux` | choose the tunnel mode (`tls`, `mux`, `direct`) |
| `pol mode 2088 tls` | change the mode of ports already forwarded |
| `pol del 2088` | stop forwarding (also `rm`; ranges work) |
| `pol list` | the forwarded ports, with live connections and traffic |
| `pol ping` | round-trip time through the tunnel |
| `pol speedtest [MB]` | speed of the tls and mux modes, both directions |

On the **server** (abroad):

| Command | What it does |
|---|---|
| `pol token` | print the join token and the install line again |
| `pol token --new` | replace the secret; relays need the new token |

On **both**:

| Command | What it does |
|---|---|
| `pol status` | connections, round-trip time, ports, traffic |
| `pol logs [-f] [-e]` | service logs (`-f` follow, `-e` problems only) |
| `pol restart` · `pol stop` · `pol start` | control the service |
| `pol tune` | turn on BBR and larger TCP buffers (recommended on both) |
| `pol update` | install the latest release, checksum verified |
| `pol uninstall` | remove pol |

Ports added or removed take effect immediately, without dropping the other ports' users. ufw rules are added and removed with them when ufw is active. If your provider has a firewall in its web panel, open the ports there yourself: the tunnel port on the server, the forwarded ports on the relay.

`pol status` on the relay:

```
╭─ pol relay ──────────────────────╮
│ version  v1.0.0  up 3h12m        │
│ server   203.0.113.7:443         │
│ tunnel 1 up  41 ms, 12 open      │
│ tunnel 2 up  40 ms, 11 open      │
╰──────────────────────────────────╯

   PORT    TARGET                 STATE      OPEN   TOTAL          UP        DOWN
   2088    127.0.0.1:2088         open         23     410    1.2 GB      18.4 GB
```

## Configuration

Everything lives in `/etc/pol/config.json` (root only). The commands edit it for you; edits by hand are picked up within two seconds on the relay.

- `relay.conns` - parallel tunnel connections (default 2). More can help on long, lossy paths.
- `relay.sni` / `server.sni` - the server name the relay announces in the TLS handshake (default `example.com`). Nothing checks it, but Iran drops TLS handshakes that have none.
- `server.any_target` - by default the server only forwards to its own ports (`127.0.0.1`). Set to `true` to let `pol add 2088:10.0.0.5:443` reach other machines.

Several Iran servers can use the same token at once.

## Installing without GitHub

If the Iran server cannot reach GitHub, download `pol-linux-amd64` from the [releases page](https://github.com/amor7/pol/releases) on a computer that can, copy it over, and run:

```bash
install -m 755 pol-linux-amd64 /usr/local/bin/pol && pol setup relay pol1_... --ports 2088
```

Later updates the same way: `pol update --file pol-linux-amd64`.

## How it works

In **mux** mode the relay keeps a few HTTP/2 connections over TLS 1.3 open to the server, and every user connection becomes one `POST` stream on one of them. The request body carries what the user sends, the response body what comes back. The server checks the secret, connects to the requested port on itself, and copies both ways. Streams are independent: each gets a 4 MB window and the connection 256 MB, so a user who stops reading only stops their own stream. Both ends ping every 15-20 seconds; a connection that stops answering is replaced, and new streams go to the least busy healthy one.

In **tls** mode the relay negotiates a different ALPN on the same port, sends one line naming the secret and the target, gets one byte back, and from then on the connection carries the user's bytes and nothing else. A few such connections are kept handshaken in advance and replaced before the server would time them out.

## Building

```bash
go test ./...
CGO_ENABLED=0 GOOS=linux go build -o pol .
```

## License

MIT
