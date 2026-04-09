# Wicket

Wicket is a multi-user, multi-network IRC bouncer written in Python. It stays
connected to IRC for you, stores history while you're away, and serves
per-device backscroll to each client that reconnects.

## Features

- **Multi-user, multi-network.** One Wicket instance can host any number of
  users, each with any number of upstream networks.
- **Per-device backscroll.** Clients identify themselves with a name in the
  password string; Wicket tracks read positions per device, so each phone,
  laptop, or IRC client only replays what *it* hasn't seen yet.
- **Persistent SQLite history.** PRIVMSGs and NOTICEs are stored on disk
  and survive restarts; on reconnect each device replays only the messages
  it hasn't seen yet. Channel events (JOIN/PART/KICK/MODE/NICK/QUIT) are
  also recorded and surfaced via opt-in `replay_activity` or the on-demand
  `ACTIVITY` command — delivered as text summaries (not real protocol
  events) so they don't desync your client's channel state.
- **Cascading configuration.** Set defaults at the top level, override per
  user, override again per network — `nick`, `realname`, rate limits,
  capabilities, replay behavior, etc.
- **IRCv3 capability negotiation.** Bouncer↔server and client↔bouncer cap
  sets are negotiated independently. Capability-dependent message formats
  (like `extended-join`) are downgraded for clients that didn't request them.
- **SASL** (PLAIN, EXTERNAL) for upstream authentication.
- **TLS** for both the listen socket and upstream connections (optional —
  plaintext is supported on either side if you'd rather terminate TLS
  elsewhere or just don't need it).
- **Built-in ident server** (RFC 1413) so you don't get the `~` prefix on
  networks that check ident.
- **Per-server rate limiting** to avoid Excess Flood disconnects.
- **Auto-reconnect** with multi-server failover.
- **Live rehash.** Reload the config file without dropping connections.
- **In-band control.** Manage the bouncer over IRC by messaging `*wicket`.
- **Activity replay.** Optionally replay channel JOINs/PARTs/KICKs/MODEs/
  NICKs/QUITs that happened while you were away, with per-channel overrides.

## Quick start

1. **Install dependencies:**
   ```
   pip install -r requirements.txt
   ```

2. **Copy and edit the example config:**
   ```
   cp config.example.yaml config.yaml
   ```
   At minimum, set a user, a password, and one network.

3. **Hash your password** (recommended over plaintext):
   ```
   python bouncer.py -c config.yaml --set-password Bob hunter2
   ```

4. **Start the bouncer:**
   ```
   python bouncer.py -c config.yaml
   ```

5. **Point your IRC client at it.** Use the password format below.

## Connecting from a client

Configure your IRC client to connect to Wicket's host/port and send a
**server password** in this format:

```
username[@clientname]/network:password
```

- `username` — the user defined in `config.yaml`
- `@clientname` — *optional* device/client identifier for per-device
  backscroll. If you connect from mIRC as `@mirc` and from your phone as
  `@phone`, each gets its own read position. Defaults to `*` if omitted.
- `network` — which configured network to attach to
- `password` — the user's password (matched against the bcrypt hash or
  plaintext in `config.yaml`)

Examples:

```
Bob@laptop/libera:hunter2
Bob@phone/libera:hunter2
Bob/oftc:hunter2
```

To attach the same client to multiple networks, open one connection per
network from your client.

## Bouncer commands

Send these as a `/msg *wicket <command>` (or to your configured `server_name`
if `delivery_source: server`):

- `HELP` — list available commands
- `STATUS` — connection status and client count for each network
- `LISTNETWORKS` — list configured networks
- `CONNECT <network>` — connect (or reconnect) to a network
- `DISCONNECT <network>` — cleanly disconnect from a network
- `SETPASSWORD <newpass>` — change your password (bcrypt-hashed and saved)
- `REHASH` — reload `config.yaml` from disk
- `ACTIVITY [#chan ...]` — replay recent JOIN/PART/KICK/MODE/NICK/QUIT
  events from history

## Documentation

See [DOCS.md](DOCS.md) for the full reference: configuration, cascading,
per-device replay, IRCv3 caps, SASL, ident, deployment, and troubleshooting.

## Known bug(s)

Note that currently the bouncer seems to have a bug where if joining channels is throttled due to 'target change too fast' (I get this on Undernet sometimes), and there's a number of channels in the line-up, it'll keep cycling through them one every couple of seconds and the target change wait time will never go down. It's hard to debug because I have to wait till I land on a server that has this join throttling again with the new log output enabled. 

## License

MIT
