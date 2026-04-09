"""YAML configuration loading and validation."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from ruamel.yaml import YAML
import bcrypt

_yaml = YAML()
_yaml.preserve_quotes = True


def hash_password(plaintext: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def set_user_password(config_path: str, username: str, new_password: str) -> None:
    """Hash a password and write it into the YAML config file for the given user.

    Preserves the rest of the file by loading/modifying/dumping the raw dict.
    """
    with open(config_path, "r", encoding="utf-8") as f:
        raw = _yaml.load(f)

    if not isinstance(raw, dict) or "users" not in raw:
        raise ValueError("Config file has no 'users' section")

    if username not in raw["users"]:
        raise ValueError(f"User '{username}' not found in config")

    raw["users"][username]["password"] = hash_password(new_password)

    with open(config_path, "w", encoding="utf-8") as f:
        _yaml.dump(raw, f)


def update_autojoin(config_path: str, username: str, network: str, channels: dict[str, str | None]) -> None:
    """Write the autojoin channel dict for a user/network to the YAML config."""
    with open(config_path, "r", encoding="utf-8") as f:
        raw = _yaml.load(f)

    if not isinstance(raw, dict) or "users" not in raw:
        raise ValueError("Config file has no 'users' section")
    if username not in raw["users"]:
        raise ValueError(f"User '{username}' not found in config")
    user_data = raw["users"][username]
    if "networks" not in user_data or network not in user_data["networks"]:
        raise ValueError(f"Network '{network}' not found for user '{username}'")

    raw["users"][username]["networks"][network]["autojoin"] = channels

    with open(config_path, "w", encoding="utf-8") as f:
        _yaml.dump(raw, f)


@dataclass
class SASLConfig:
    mechanism: str = "PLAIN"
    username: str = ""
    password: str = ""
    cert_path: Optional[str] = None  # For EXTERNAL


@dataclass
class ServerConfig:
    host: str = "localhost"
    port: int = 6697
    tls: bool = True
    tls_verify: bool = True
    password: Optional[str] = None  # Server password (PASS command)


@dataclass
class NetworkConfig:
    name: str = ""
    servers: list[ServerConfig] = field(default_factory=list)
    nick: str = "wicket"
    alt_nicks: list[str] = field(default_factory=list)
    user: str = "wicket"
    ident_username: str = ""  # Ident response; defaults to user if empty
    realname: str = "Wicket IRC Bouncer"
    password: Optional[str] = None  # Network-level server password (PASS), servers can override
    sasl: Optional[SASLConfig] = None
    autojoin: dict[str, str | None] = field(default_factory=dict)  # channel -> key or None
    rate_limit_ms: int = 500
    auto_connect: bool = True
    caps_wanted: list[str] = field(default_factory=list)
    upstream_caps: Optional[list[str]] = None  # Full override for upstream caps (None = use defaults)
    downstream_caps: Optional[list[str]] = None  # Full override for downstream caps (None = use defaults)
    replay_activity: bool = False  # Auto-send activity (JOIN/PART/KICK/MODE/NICK/QUIT) on connect
    replay_activity_target: str = "channel"  # "channel" or "bouncer" — where to send replayed activity lines
    channel_replay_activity: dict[str, bool] = field(default_factory=dict)  # Per-channel overrides


@dataclass
class UserConfig:
    username: str = ""
    password: str = ""  # bcrypt hash or plaintext (bcrypt preferred)
    nick: str = ""  # Default nick for all networks (defaults to username)
    alt_nicks: list[str] = field(default_factory=list)  # Default alt_nicks for all networks
    user: str = ""  # Default user/ident for all networks (defaults to username)
    ident_username: str = ""  # Default ident response for all networks (defaults to user)
    realname: str = ""  # Default realname for all networks
    auto_connect: bool = True  # Default auto_connect for all networks
    rate_limit_ms: int = 500  # Default rate limit for all networks
    caps_wanted: list[str] = field(default_factory=list)  # Default extra caps for all networks
    upstream_caps: Optional[list[str]] = None  # Full override for upstream caps
    downstream_caps: Optional[list[str]] = None  # Full override for downstream caps
    replay_activity: bool = False  # Default replay_activity for all networks
    replay_activity_target: str = "channel"  # Default target for all networks
    networks: dict[str, NetworkConfig] = field(default_factory=dict)
    delivery: str = "notice"  # "notice" or "privmsg"
    delivery_source: str = "*wicket"  # "*wicket" or "server"


@dataclass
class ListenConfig:
    host: str = "0.0.0.0"
    port: int = 6697
    tls: bool = True
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None


@dataclass
class LoggingConfig:
    level: str = "info"  # debug, info, warning, error
    file: Optional[str] = None  # Log file path (None = stderr only)
    max_bytes: int = 10_000_000  # 10 MB default for rotation
    backup_count: int = 5  # Number of rotated log files to keep
    log_irc: bool = False  # Log raw IRC traffic (very verbose)


@dataclass
class IdentConfig:
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 113


@dataclass
class BouncerConfig:
    listen: ListenConfig = field(default_factory=ListenConfig)
    database: str = "wicket.db"
    users: dict[str, UserConfig] = field(default_factory=dict)
    server_name: str = "wicket"
    motd: Optional[str] = None
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    ident: IdentConfig = field(default_factory=IdentConfig)
    # Top-level defaults (overridden by user level, then network level)
    nick: str = ""  # defaults to username if empty
    alt_nicks: list[str] = field(default_factory=list)
    user: str = ""  # defaults to username if empty
    ident_username: str = ""  # defaults to user if empty
    realname: str = "Wicket User"
    delivery: str = "notice"
    delivery_source: str = "*wicket"
    caps_wanted: list[str] = field(default_factory=list)
    upstream_caps: Optional[list[str]] = None
    downstream_caps: Optional[list[str]] = None
    rate_limit_ms: int = 500
    auto_connect: bool = True
    replay_activity: bool = False
    replay_activity_target: str = "channel"

    @staticmethod
    def load(path: str) -> BouncerConfig:
        with open(path, "r", encoding="utf-8") as f:
            raw = _yaml.load(f)

        if not isinstance(raw, dict):  # CommentedMap is a dict subclass
            raise ValueError("Config must be a YAML mapping")

        config = BouncerConfig()

        # Listen section
        if "listen" in raw:
            ls = raw["listen"]
            config.listen = ListenConfig(
                host=ls.get("host", "0.0.0.0"),
                port=ls.get("port", 6697),
                tls=ls.get("tls", True),
                tls_cert=ls.get("tls_cert"),
                tls_key=ls.get("tls_key"),
            )

        config.database = raw.get("database", "wicket.db")
        config.server_name = raw.get("server_name", "wicket")
        config.motd = raw.get("motd")

        # Top-level defaults for cascading settings
        config.nick = raw.get("nick", "")
        config.alt_nicks = raw.get("alt_nicks", [])
        config.user = raw.get("user", "")
        config.ident_username = raw.get("ident_username", "")
        config.realname = raw.get("realname", "Wicket User")
        config.delivery = raw.get("delivery", "notice")
        config.delivery_source = raw.get("delivery_source", "*wicket")
        config.caps_wanted = raw.get("caps_wanted", [])
        config.rate_limit_ms = raw.get("rate_limit_ms", 500)
        config.upstream_caps = raw.get("upstream_caps")
        config.downstream_caps = raw.get("downstream_caps")
        config.auto_connect = raw.get("auto_connect", True)
        config.replay_activity = raw.get("replay_activity", False)
        config.replay_activity_target = raw.get("replay_activity_target", "channel")

        # Logging section
        if "logging" in raw:
            lg = raw["logging"]
            config.logging = LoggingConfig(
                level=lg.get("level", "info"),
                file=lg.get("file"),
                max_bytes=lg.get("max_bytes", 10_000_000),
                backup_count=lg.get("backup_count", 5),
                log_irc=lg.get("log_irc", False),
            )

        # Ident section
        if "ident" in raw:
            id_cfg = raw["ident"]
            config.ident = IdentConfig(
                enabled=id_cfg.get("enabled", False),
                host=id_cfg.get("host", "0.0.0.0"),
                port=id_cfg.get("port", 113),
            )

        # Users section
        if "users" in raw:
            for uname, udata in raw["users"].items():
                # User-level defaults cascade from top-level
                # nick/user default to username if neither user nor top-level sets them
                user_nick = udata.get("nick", config.nick or uname)
                user_alt_nicks = udata.get("alt_nicks", config.alt_nicks)
                user_user = udata.get("user", config.user or uname)
                user_ident = udata.get("ident_username", config.ident_username)
                user_realname = udata.get("realname", config.realname)
                user_auto_connect = udata.get("auto_connect", config.auto_connect)
                user_rate_limit_ms = udata.get("rate_limit_ms", config.rate_limit_ms)
                user_caps_wanted = udata.get("caps_wanted", config.caps_wanted)
                user_delivery = udata.get("delivery", config.delivery)
                user_delivery_source = udata.get("delivery_source", config.delivery_source)
                user_upstream_caps = udata.get("upstream_caps", config.upstream_caps)
                user_downstream_caps = udata.get("downstream_caps", config.downstream_caps)
                user_replay_activity = udata.get("replay_activity", config.replay_activity)
                user_replay_activity_target = udata.get("replay_activity_target", config.replay_activity_target)

                uc = UserConfig(
                    username=uname,
                    password=udata.get("password", ""),
                    nick=user_nick,
                    alt_nicks=user_alt_nicks,
                    user=user_user,
                    ident_username=user_ident,
                    realname=user_realname,
                    auto_connect=user_auto_connect,
                    rate_limit_ms=user_rate_limit_ms,
                    caps_wanted=user_caps_wanted,
                    delivery=user_delivery,
                    delivery_source=user_delivery_source,
                    upstream_caps=user_upstream_caps,
                    downstream_caps=user_downstream_caps,
                    replay_activity=user_replay_activity,
                    replay_activity_target=user_replay_activity_target,
                )

                if "networks" in udata:
                    for nname, ndata in udata["networks"].items():
                        # Parse servers: supports "server" (single) or "servers" (list)
                        servers: list[ServerConfig] = []
                        if "servers" in ndata:
                            for sc_data in ndata["servers"]:
                                servers.append(ServerConfig(
                                    host=sc_data.get("host", "localhost"),
                                    port=sc_data.get("port", 6697),
                                    tls=sc_data.get("tls", True),
                                    tls_verify=sc_data.get("tls_verify", True),
                                    password=sc_data.get("password"),
                                ))
                        elif "server" in ndata:
                            sc_data = ndata["server"]
                            servers.append(ServerConfig(
                                host=sc_data.get("host", "localhost"),
                                port=sc_data.get("port", 6697),
                                tls=sc_data.get("tls", True),
                                tls_verify=sc_data.get("tls_verify", True),
                                password=sc_data.get("password"),
                            ))

                        sasl = None
                        if "sasl" in ndata:
                            sd = ndata["sasl"]
                            sasl = SASLConfig(
                                mechanism=sd.get("mechanism", "PLAIN"),
                                username=sd.get("username", ""),
                                password=sd.get("password", ""),
                                cert_path=sd.get("cert_path"),
                            )

                        # Parse autojoin: supports both list and dict formats
                        # List: ["#chan1", "#chan2"]
                        # Dict: {"#chan1": null, "#chan2": "key"}
                        raw_autojoin = ndata.get("autojoin", {})
                        if isinstance(raw_autojoin, list):
                            autojoin = {ch: None for ch in raw_autojoin}
                        elif isinstance(raw_autojoin, dict):
                            autojoin = raw_autojoin
                        else:
                            autojoin = {}

                        # Parse channel_replay_activity overrides
                        raw_chan_activity = ndata.get("channel_replay_activity", {})
                        chan_activity = {}
                        if isinstance(raw_chan_activity, dict):
                            chan_activity = {k.lower(): bool(v) for k, v in raw_chan_activity.items()}

                        # Network overrides user-level defaults
                        nc = NetworkConfig(
                            name=nname,
                            servers=servers,
                            nick=ndata.get("nick", user_nick),
                            alt_nicks=ndata.get("alt_nicks", user_alt_nicks),
                            user=ndata.get("user", user_user),
                            ident_username=ndata.get("ident_username", user_ident),
                            realname=ndata.get("realname", user_realname),
                            password=ndata.get("password"),
                            sasl=sasl,
                            autojoin=autojoin,
                            rate_limit_ms=ndata.get("rate_limit_ms", user_rate_limit_ms),
                            auto_connect=ndata.get("auto_connect", user_auto_connect),
                            caps_wanted=ndata.get("caps_wanted", user_caps_wanted),
                            upstream_caps=ndata.get("upstream_caps", user_upstream_caps),
                            downstream_caps=ndata.get("downstream_caps", user_downstream_caps),
                            replay_activity=ndata.get("replay_activity", user_replay_activity),
                            replay_activity_target=ndata.get("replay_activity_target", user_replay_activity_target),
                            channel_replay_activity=chan_activity,
                        )
                        uc.networks[nname] = nc

                config.users[uname] = uc

        return config
