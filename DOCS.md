# Wicket Documentation

A complete reference for configuring and using the Wicket IRC bouncer.

---

## Table of contents

1. [Installation](#installation)
2. [Running Wicket](#running-wicket)
3. [Command-line flags](#command-line-flags)
4. [Connecting clients](#connecting-clients)
5. [The password format](#the-password-format)
6. [Per-device backscroll](#per-device-backscroll)
7. [Configuration file](#configuration-file)
8. [Cascading settings](#cascading-settings)
9. [Networks and servers](#networks-and-servers)
10. [SASL](#sasl)
11. [Autojoin](#autojoin)
12. [Activity replay](#activity-replay)
13. [IRCv3 capabilities](#ircv3-capabilities)
14. [Rate limiting](#rate-limiting)
15. [TLS](#tls)
16. [Ident server](#ident-server)
17. [Logging](#logging)
18. [Bouncer commands](#bouncer-commands)
19. [Live rehash](#live-rehash)
20. [Database](#database)
21. [Deployment notes](#deployment-notes)
22. [Troubleshooting](#troubleshooting)

---

## Installation

Wicket requires Python 3.10+ (uses PEP 604 union types and `dict[...]`
generics natively).

```
pip install -r requirements.txt
```

Dependencies: `ruamel.yaml`, `bcrypt`, and the standard library.

---

## Running Wicket

```
python bouncer.py -c config.yaml
```

Wicket will:

1. Open the SQLite database (creating it if missing).
2. Start the optional ident server.
3. Bind the listen socket. *If the bind fails, Wicket exits before
   touching any upstream networks* — no spurious connect/quit churn.
4. Connect to all upstream networks whose `auto_connect` is true.
5. Serve forever.

On Unix, `SIGINT`/`SIGTERM` cause a graceful shutdown and `SIGHUP`
triggers a config rehash.

---

## Command-line flags

| Flag | Description |
|---|---|
| `-c PATH`, `--config PATH` | Path to YAML config file (**required**) |
| `-v`, `--verbose` | `-v` for debug logging, `-vv` for debug + raw IRC traffic |
| `--log-file PATH` | Log to a file (overrides config) |
| `--set-password USERNAME PASSWORD` | Hash a password into `config.yaml` and exit |

`--set-password` is the recommended way to seed a user's password; it
runs through bcrypt and writes the hash back to the YAML file with the
rest of the file preserved (comments and all).

---

## Connecting clients

Point any IRC client at Wicket's `listen.host` and `listen.port`. If
`listen.tls` is true, use a TLS-enabled server entry in your client.

For each network you want to attach to, open a separate connection from
your client (most clients let you define multiple "servers" or
"networks"). Each connection sends its own password specifying which
network to attach to.

---

## The password format

Wicket expects the **server password** field to be:

```
username[@clientname]/network:password
```

Where:

- **`username`** — the user key under `users:` in `config.yaml`.
- **`@clientname`** — *optional*. An identifier for the device or
  client you're connecting from. It can be any string without `/`,
  `:`, `@`, or whitespace. If omitted, the identifier defaults to `*`.
- **`network`** — the network key under that user's `networks:`.
- **`password`** — the user's password. Matched against the user's
  `password` field, which may be a bcrypt hash (preferred) or
  plaintext.

### Examples

| String | Means |
|---|---|
| `Bob/libera:hunter2` | User `Bob`, network `libera`, identifier `*` |
| `Bob@laptop/libera:hunter2` | Identifier `laptop` |
| `Bob@phone/libera:hunter2` | Same user, different identifier |
| `Bob@mirc/oftc:hunter2` | Different network |

Whatever your client puts in its "server password" field is what
Wicket parses. In mIRC this is the **Password** box on the server
entry; in HexChat it's "Server password (PASS)"; in irssi it's the
`-password` argument to `/connect`.

---

## Per-device backscroll

Wicket stores every received message in SQLite and tracks a separate
**read position** per `(user, network, identifier, target)` tuple.

That means if you've configured Bob to connect from two devices —
say, `Bob@laptop/libera` and `Bob@phone/libera` — each device will
only receive backscroll for messages it hasn't seen yet. When the
laptop disconnects, its read position is saved at the latest message
ID; when it reconnects later, replay starts from that ID, skipping
anything the phone has already delivered to itself.

If you connect with no identifier (`Bob/libera:...`), all such
unidentified connections share the `*` slot.

Read positions are saved on disconnect (including unclean
disconnects, as long as the TCP socket closes). They are also saved
when a client sends `QUIT`.

---

## Configuration file

Wicket reads a YAML file. The full annotated example lives in
`config.example.yaml`. The minimal viable config is:

```yaml
listen:
  host: "0.0.0.0"
  port: 6697
  tls: false

database: "wicket.db"
server_name: "wicket"

users:
  Bob:
    password: "hunter2"
    networks:
      libera:
        server:
          host: "irc.libera.chat"
          port: 6697
          tls: true
        autojoin:
          - "#python"
```

### Top-level keys

| Key | Type | Default | Notes |
|---|---|---|---|
| `listen` | object | — | Listen socket config (see below) |
| `database` | string | `"wicket.db"` | SQLite database path |
| `server_name` | string | `"wicket"` | Name advertised to clients in numerics |
| `motd` | string \| null | `null` | Optional MOTD shown to clients |
| `logging` | object | — | Logging config |
| `ident` | object | — | Ident server config |
| `users` | map | `{}` | Users keyed by username |
| *cascading defaults* | — | — | See [Cascading settings](#cascading-settings) |

### `listen`

| Key | Type | Default |
|---|---|---|
| `host` | string | `"0.0.0.0"` |
| `port` | int | `6697` |
| `tls` | bool | `true` |
| `tls_cert` | string | required if `tls: true` |
| `tls_key` | string | required if `tls: true` |

If `tls: true` and the cert/key are missing or unreadable, Wicket
exits with an error rather than silently falling back to plaintext.

---

## Cascading settings

Several settings can be defined at three (sometimes four) levels.
Each level overrides the one above it:

1. **Top level** — applies to all users and networks
2. **User level** — applies to all of that user's networks
3. **Network level** — applies to one specific network
4. **Channel level** — only `replay_activity` supports this, via
   `channel_replay_activity` at the network level

Cascading settings:

`nick`, `alt_nicks`, `user`, `ident_username`, `realname`,
`delivery`, `delivery_source`, `auto_connect`, `rate_limit_ms`,
`caps_wanted`, `upstream_caps`, `downstream_caps`, `replay_activity`,
`replay_activity_target`

Defaults:

- `nick` and `user` default to the **username** if not set anywhere.
- `ident_username` defaults to `user` if not set.

---

## Networks and servers

Each network entry must define either `server` (single) or `servers`
(list, tried in order on failure):

```yaml
libera:
  server:
    host: "irc.libera.chat"
    port: 6697
    tls: true
    tls_verify: true
    password: "optional-server-pass"
```

```yaml
libera:
  servers:
    - host: "irc.libera.chat"
      port: 6697
      tls: true
    - host: "irc.us.libera.chat"
      port: 6697
      tls: true
```

When using `servers:`, Wicket tries each entry in order on connect
failure, and on disconnect/reconnect cycles through the list.

### Per-server options

| Key | Type | Default |
|---|---|---|
| `host` | string | `"localhost"` |
| `port` | int | `6697` |
| `tls` | bool | `true` |
| `tls_verify` | bool | `true` |
| `password` | string \| null | inherits network-level `password` |

A network-level `password:` is used as the server `PASS` for all
servers in that network unless overridden per-server.

---

## SASL

SASL is optional — omit the `sasl:` block entirely to skip it. There is
no "require SASL" mode; if SASL is configured and fails, Wicket logs a
warning and continues registering without authentication.

```yaml
sasl:
  mechanism: "PLAIN"
  username: "Atreyu"
  password: "drawssap"
```

Supported mechanisms: `PLAIN`, `EXTERNAL`. For `EXTERNAL` (client
certificate auth), set `cert_path` instead of password:

```yaml
sasl:
  mechanism: "EXTERNAL"
  cert_path: "/path/to/client-cert.pem"
```

---

## Autojoin

Two formats are accepted:

```yaml
autojoin:
  - "#python"
  - "#asyncio"
```

```yaml
autojoin:
  "#linux": null
  "#chat": "open_sesame"
```

The dict form lets you specify channel keys. `null` means no key.

When you `/join` or `/part` a channel through Wicket, the autojoin
list is updated and persisted to `config.yaml` automatically (with
formatting/comments preserved).

If a channel join is rejected by the server with "target change too
fast" (numerics 439, 480, or 263), Wicket schedules a retry using
the wait time the server suggested, deduping retries per channel so
the queue doesn't pile up.

---

## Activity replay

PRIVMSGs and NOTICEs are always replayed from the backscroll on
reconnect, up to each device's last read position.

Channel events (JOIN/PART/KICK/MODE/NICK/QUIT) are **not** replayed by
default, but can be enabled with `replay_activity: true`. They are
delivered as **text summaries** rather than as real protocol events —
i.e. as a PRIVMSG/NOTICE line saying `[14:32] alice joined #linux`,
not as a real `JOIN` from alice. This deliberately avoids desyncing
your client's channel state: replayed real JOINs would add ghost
members, replayed MODEs would look like fresh mode flips, and so on.

### Where activity lines go: `replay_activity_target`

| Value | Behavior |
|---|---|
| `channel` (default) | Activity lines for a channel are delivered into that channel's window, so events appear in context. |
| `bouncer` | All activity lines go to wherever other bouncer messages go, which depends on your `delivery_source`: a query window with `*wicket` (default) or your server/status window (`delivery_source: server`). |

`NICK` and `QUIT` are global events with no specific channel, so they
always go to the bouncer window regardless of this setting.

`replay_activity_target` cascades the same way as other settings (top
→ user → network).

Enable globally:

```yaml
replay_activity: true
```

Or per-user / per-network. Per-channel overrides live under the
network entry:

```yaml
networks:
  libera:
    replay_activity: true
    channel_replay_activity:
      "#linux": true          # show activity even if network default is false
      "#busy-channel": false  # suppress activity on a noisy channel
```

You can also pull activity on-demand via the `ACTIVITY` bouncer
command (see below).

---

## IRCv3 capabilities

Wicket negotiates capabilities **separately** with upstream servers
and with downstream clients. A client may advertise different caps
than the server it's attached to; Wicket bridges them and downgrades
where necessary (for example, stripping the `account` and `realname`
parameters from `extended-join` messages when forwarding to a client
that didn't request `extended-join`).

| Setting | Effect |
|---|---|
| `caps_wanted` | Extra caps to request beyond the built-in defaults |
| `upstream_caps` | Full override of caps requested from servers |
| `downstream_caps` | Full override of caps advertised to clients |

`upstream_caps` and `downstream_caps` are full overrides — set them
to `null` (the default) to use Wicket's built-in defaults.

---

## Rate limiting

Per-server rate limiting prevents Excess Flood disconnects. Configure
`rate_limit_ms` (minimum milliseconds between messages sent to a
server) at any cascade level.

Suggested values:

| Network | Suggested `rate_limit_ms` |
|---|---|
| Libera, OFTC | 500 |
| EFnet, Undernet, DALnet | 1000 |
| IRCnet | 2000–3000 |
| QuakeNet, Rizon | 500 |

If you see Excess Flood disconnects, increase this value.

---

## TLS

Wicket supports TLS on both ends:

- **Listen socket TLS** is enabled with `listen.tls: true` and
  `tls_cert` / `tls_key`. Minimum version is TLS 1.2. Wicket exits if
  the cert or key is missing or invalid.
- **Upstream TLS** is enabled per-server with `tls: true`.
  `tls_verify: true` enables certificate verification (the default).

For Let's Encrypt:

```yaml
listen:
  tls_cert: "/etc/letsencrypt/live/example.com/fullchain.pem"
  tls_key: "/etc/letsencrypt/live/example.com/privkey.pem"
```

---

## Ident server

```yaml
ident:
  enabled: true
  host: "0.0.0.0"
  port: 113
```

The ident server (RFC 1413) responds to upstream IRC servers' ident
queries so your nick doesn't get the `~` prefix. The response uses
the network's `ident_username` (or `user` if not set).

Port 113 typically requires root/admin. On Linux, either run Wicket
as root, give the binary `CAP_NET_BIND_SERVICE`, or run on a high
port and forward 113 → that port via iptables. On Windows, run as
Administrator. Some ISPs block port 113 entirely; Wicket logs but
does not error in that case.

---

## Logging

```yaml
logging:
  level: "info"           # debug, info, warning, error
  file: "/var/log/wicket.log"
  max_bytes: 10000000     # 10 MB rotation threshold
  backup_count: 5         # number of rotated files to keep
  log_irc: false          # log raw IRC traffic (very verbose)
```

CLI overrides:

- `-v` forces level to debug
- `-vv` forces level to debug *and* enables raw IRC traffic logging
- `--log-file PATH` overrides `logging.file`

Logs always go to stderr in addition to any log file.

---

## Bouncer commands

Send commands as `/msg *wicket <command>` from any attached client.
If you've set `delivery_source: server`, send them to your
configured `server_name` instead (most clients route this to the
"server" or "status" window).

| Command | Description |
|---|---|
| `HELP` | List available commands |
| `STATUS` | Show connection status and client count for each network |
| `LISTNETWORKS` | List all configured networks and connection state |
| `CONNECT <network>` | Connect (or reconnect) to a network |
| `DISCONNECT <network>` | Cleanly disconnect from a network without stopping the bouncer |
| `SETPASSWORD <newpass>` | Change your password (bcrypt-hashed and saved to `config.yaml`) |
| `REHASH` | Reload `config.yaml` from disk and apply safe changes |
| `ACTIVITY [channel\|bouncer] [#chan ...]` | Replay recent JOIN/PART/KICK/MODE/NICK/QUIT from history. The first arg may be `channel` or `bouncer` to override `replay_activity_target` for this invocation. Remaining `#chan` args filter to those channels. |

`CONNECT` is also how you bring up networks that have
`auto_connect: false`, or networks you previously took down with
`DISCONNECT`.

`SETPASSWORD` requires the new password to be at least 4 characters.
The hash is stored both in memory and in the YAML file (preserving
formatting). If the file write fails (e.g. read-only mount), the
in-memory password still updates and a warning is logged.

---

## Live rehash

`REHASH` (or `SIGHUP` on Unix) reloads `config.yaml` and applies
changes without dropping connections.

**Safe changes** (applied immediately):

- Logging configuration
- Top-level cascading defaults
- Per-user passwords, delivery, delivery_source
- Per-network `rate_limit_ms` (live-applied to active connections)
- Autojoin lists, `auto_connect`, capability lists
- `replay_activity` and `replay_activity_target` settings
- New users
- New networks (auto-connected if configured)

**Changes that need a reconnect to take effect** (config is updated
in memory; next reconnect uses the new values):

- `nick`, `user`, `realname`, `ident_username`
- SASL configuration
- Server list

**Removed users/networks** are not disconnected; you must restart
Wicket to drop them.

---

## Database

Wicket uses SQLite (WAL mode) at the path given by `database:`.
Schema is created on first run. Tables track:

- Messages (PRIVMSG, NOTICE, channel events)
- Read positions per `(user, network, identifier, target)`
- Channel autojoin state mirroring config (used for crash recovery)

The database is the source of truth for backscroll. Deleting it
will reset all read positions and lose history but will not break
the bouncer.

---

## Deployment notes

- **Bind before connect.** Wicket binds the listen socket before
  connecting to any upstream network, so a port-in-use error fails
  fast without spamming connect/quit on IRC.
- **Graceful shutdown.** On `SIGINT`/`SIGTERM`, Wicket disconnects
  upstreams with a `QUIT`, closes downstreams, flushes the database,
  and exits within ~5 seconds.
- **Systemd:** a typical unit runs `python /opt/wicket/bouncer.py
  -c /etc/wicket/config.yaml` as a non-root user. Use
  `Restart=on-failure` and consider `AmbientCapabilities=CAP_NET_BIND_SERVICE`
  if you want ports < 1024 without root.
- **Some ISPs block IRC ports** (6660–6669, sometimes 6660–6699) on
  inbound listens. Pick a non-IRC port like 16667 or 7000 if you
  hit this.

---

## Troubleshooting

**"You must provide a password (PASS command)"** — Your IRC client
isn't sending a server password, or is sending it after `NICK`/`USER`
in a way Wicket doesn't see in time. Set the **server password**
field, not NickServ.

**"Invalid password format"** — Your password string didn't match
`username[@clientname]/network:password`. Check for typos, missing
`/`, or whitespace.

**"Unknown network"** — The `network` part of your password doesn't
match any of that user's `networks:` keys. Use `LISTNETWORKS` from
an attached session to see what's configured.

**Excess Flood disconnects** — Increase `rate_limit_ms` for the
network in question.

**Wrong channels being joined (e.g. your realname)** — Your client
doesn't support `extended-join`. Wicket downgrades JOIN messages
automatically; if you still see this, make sure you're on a recent
build.

**Backscroll replays messages you've already seen** — Read positions
are saved on disconnect. If your client crashes mid-session before
sending `QUIT` and the TCP socket isn't cleanly closed, the last
read position may not be saved. Reconnect and disconnect cleanly to
update it.

**Ident shows `~` prefix anyway** — Either ident isn't enabled,
your ISP blocks port 113, or the IRC server didn't query in time.
Check Wicket's logs for ident activity.

**Port 16667 already in use** — Something else is bound. On Windows
the offender might be running in WSL and won't appear in
`tasklist`; check `netstat -ano` and your WSL distro.
