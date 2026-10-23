"""YAML configuration loading and validation."""

from __future__ import annotations
from dataclasses import dataclass, field, fields
import datetime
import difflib
import functools
import types
import typing
from typing import Literal, Optional
from ruamel.yaml import YAML
from ruamel.yaml.scalarbool import ScalarBoolean
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
    mechanism: Literal["PLAIN", "EXTERNAL"] = "PLAIN"
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
    # After an *unclean* disconnect (local socket/network abort — not a clean
    # server-initiated close), wait at least this many seconds before
    # reconnecting.  The server keeps our old session as a "ghost" until its
    # PING timeout; reconnecting sooner makes the ghost and the new session both
    # count against the server's per-IP connection limit, which can trigger an
    # "excessive connections" auto-ban (e.g. undernet ex-conn G-line).  Should
    # be larger than the network's PING timeout (~2-3 min on undernet).  0
    # disables the wait (fast reconnect even after an unclean drop).
    unclean_reconnect_delay: float = 240.0
    auto_connect: bool = True
    caps_wanted: list[str] = field(default_factory=list)
    upstream_caps: Optional[list[str]] = None  # Full override for upstream caps (None = use defaults)
    downstream_caps: Optional[list[str]] = None  # Full override for downstream caps (None = use defaults)
    replay_activity: bool = False  # Auto-send activity (JOIN/PART/KICK/MODE/NICK/QUIT) on connect
    replay_activity_target: Literal["channel", "bouncer"] = "channel"  # where to send replayed activity lines
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
    unclean_reconnect_delay: float = 240.0  # Default ghost-reap reconnect delay for all networks
    caps_wanted: list[str] = field(default_factory=list)  # Default extra caps for all networks
    upstream_caps: Optional[list[str]] = None  # Full override for upstream caps
    downstream_caps: Optional[list[str]] = None  # Full override for downstream caps
    replay_activity: bool = False  # Default replay_activity for all networks
    replay_activity_target: Literal["channel", "bouncer"] = "channel"  # Default target for all networks
    networks: dict[str, NetworkConfig] = field(default_factory=dict)
    delivery: Literal["notice", "privmsg"] = "notice"
    delivery_source: str = "*wicket"  # "server", or the nick bouncer messages come from


@dataclass
class ListenConfig:
    host: str = "0.0.0.0"
    port: int = 6697
    tls: bool = True
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None


@dataclass
class LoggingConfig:
    level: Literal["debug", "info", "warning", "warn", "error", "critical", "fatal"] = "info"
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
    delivery: Literal["notice", "privmsg"] = "notice"
    delivery_source: str = "*wicket"
    caps_wanted: list[str] = field(default_factory=list)
    upstream_caps: Optional[list[str]] = None
    downstream_caps: Optional[list[str]] = None
    rate_limit_ms: int = 500
    unclean_reconnect_delay: float = 240.0
    auto_connect: bool = True
    replay_activity: bool = False
    replay_activity_target: Literal["channel", "bouncer"] = "channel"

    @staticmethod
    def load(path: str) -> BouncerConfig:
        """Read and check the config file at `path`.

        Raises ConfigError listing every problem -- a value that is not what its
        key holds, a key Wicket does not read -- and builds nothing from a file
        that has any.
        """
        with open(path, "r", encoding="utf-8") as f:
            raw = _yaml.load(f)

        if not isinstance(raw, dict):  # CommentedMap is a dict subclass
            raise ValueError("Config must be a YAML mapping")

        errors: list[str] = []
        config = _build_bouncer(raw, errors)
        if errors:
            raise ConfigError(errors)
        return config


# --- Loading ------------------------------------------------------------------
#
# The dataclasses above are the schema: a field's annotation says what its key
# may hold, and its default applies when no level sets it.  Values are stored as
# given and used far from here, so one of the wrong type would fail at the point
# of use with nothing naming the key; each is therefore checked as it is read,
# and so is every key, since a misspelt one would otherwise be silently ignored.


class ConfigError(ValueError):
    """The file is valid YAML, but some of what it says cannot be used.

    `errors` holds one line per problem, each starting with the key's dotted path.
    """

    def __init__(self, errors: list[str]):
        super().__init__(errors)
        self.errors = errors

    def __str__(self) -> str:
        noun = "problem" if len(self.errors) == 1 else "problems"
        return "\n".join([f"{len(self.errors)} {noun} in the config:"]
                         + ["  " + e for e in self.errors])


# Settings that cascade: set at the top level or on a user, they apply to every
# level below that has the same field, unless that level sets its own.  Listed
# rather than derived from the fields the levels share, because a shared name is
# not a shared meaning: a user's `password` logs in to Wicket, a network's is the
# PASS sent to its server.
CASCADING = frozenset({
    "nick", "alt_nicks", "user", "ident_username", "realname",
    "delivery", "delivery_source", "auto_connect", "rate_limit_ms",
    "unclean_reconnect_delay", "caps_wanted", "upstream_caps",
    "downstream_caps", "replay_activity", "replay_activity_target",
})

# Fields whose values are never repeated in a message (autojoin holds channel keys).
_SECRETS = frozenset({"password", "autojoin"})


def _autojoin(value) -> dict:
    """autojoin as written -- a list of channels, a mapping of channel to key,
    or empty -- as the mapping of channel to key (None for no key)."""
    if isinstance(value, list):
        return {ch: None for ch in value}
    return value or {}


def _replay_overrides(value) -> dict:
    """channel_replay_activity as written (or empty), keyed by lowercase channel."""
    return {k.lower(): v for k, v in (value or {}).items()}


# Fields whose YAML form is not the stored form:
# field name -> (what the key may hold, how to make the stored value from it).
_YAML_FORMS = {
    "autojoin": (list[str] | dict[str, str | None] | None, _autojoin),
    "channel_replay_activity": (dict[str, bool] | None, _replay_overrides),
}


def _build_bouncer(raw, errors: list[str]) -> BouncerConfig:
    sections = ("listen", "logging", "ident", "users")
    config = BouncerConfig(**_read(BouncerConfig, raw, "", errors,
                                   filled=sections, keys=sections))
    for key, cls in (("listen", ListenConfig), ("logging", LoggingConfig),
                     ("ident", IdentConfig)):
        section = _section(raw, key, "", errors)
        if section is not None:
            setattr(config, key, cls(**_read(cls, section, key, errors)))
    for uname, udata, upath in _named(raw, "users", "", errors):
        config.users[uname] = _build_user(uname, udata, upath, config, errors)
    return config


def _build_user(uname: str, udata, path: str, parent: BouncerConfig,
                errors: list[str]) -> UserConfig:
    uc = UserConfig(username=uname, **_read(
        UserConfig, udata, path, errors, parent=parent,
        filled=("username", "networks"), keys=("networks",)))
    # nick and user default to the user's own name when no level sets them.
    uc.nick = uc.nick or uname
    uc.user = uc.user or uname
    for nname, ndata, npath in _named(udata, "networks", path, errors):
        uc.networks[nname] = _build_network(nname, ndata, npath, uc, errors)
    return uc


def _build_network(nname: str, ndata, path: str, parent: UserConfig,
                   errors: list[str]) -> NetworkConfig:
    nc = NetworkConfig(name=nname, **_read(
        NetworkConfig, ndata, path, errors, parent=parent,
        filled=("name", "servers", "sasl"), keys=("server", "servers", "sasl")))

    # One server is written `server: {...}`, several `servers: [{...}, ...]`.
    reported = len(errors)
    if "server" in ndata and "servers" in ndata:
        errors.append(f"{path}: has both server and servers; keep one")
    elif "servers" in ndata:
        spath = _join(path, "servers")
        if not isinstance(ndata["servers"], list):
            errors.append(f"{spath}: should be a list of servers, "
                          f"but YAML read it as {_describe(ndata['servers'])}")
        else:
            for i, body in enumerate(ndata["servers"]):
                body = _as_mapping(body, f"{spath}[{i}]", errors)
                if body is not None:
                    nc.servers.append(_build_server(body, f"{spath}[{i}]", errors))
    elif "server" in ndata:
        body = _section(ndata, "server", path, errors)
        if body is not None:
            nc.servers.append(_build_server(body, _join(path, "server"), errors))
    if not nc.servers and len(errors) == reported:
        errors.append(f"{path}: has no server; add server: with at least a host")

    sasl = _section(ndata, "sasl", path, errors)
    if sasl is not None:
        nc.sasl = SASLConfig(**_read(SASLConfig, sasl, _join(path, "sasl"), errors))
    return nc


def _build_server(body, path: str, errors: list[str]) -> ServerConfig:
    # ServerConfig defaults the host to localhost, which is a default for
    # nothing anyone means to write; leaving it out is a mistake.
    if "host" not in body:
        errors.append(f"{path}: has no host")
    return ServerConfig(**_read(ServerConfig, body, path, errors))


def _read(cls, raw, path: str, errors: list[str], *, parent=None,
          filled=(), keys=()) -> dict:
    """Keyword arguments for `cls` from the YAML section `raw`, every value checked.

    path: the section's dotted name in messages ("" for the top level).
    parent: the enclosing level's config.  A CASCADING field `raw` does not
        set takes its value from there; any other field it does not set is left
        out, so the dataclass default applies.
    filled: fields the caller fills itself (nested sections, a user's name).
    keys: keys of `raw` the caller reads itself.  With the fields not in
        `filled`, these are all the keys the section may have; any other is
        reported.
    A value that does not check out is reported and left out.
    """
    hints = _hints(cls)
    out = {}
    for name, hint in hints.items():
        if name in filled:
            continue
        if name in raw:
            accepted, convert = _YAML_FORMS.get(name, (hint, None))
            value = raw[name]
            if _check(value, accepted, _join(path, name), errors,
                      secret=name in _SECRETS):
                value = _canonical(value, accepted)
                out[name] = convert(value) if convert else value
        elif parent is not None and name in CASCADING and hasattr(parent, name):
            out[name] = getattr(parent, name)

    allowed = (set(hints) - set(filled)) | set(keys)
    for key in raw:
        if key not in allowed:
            msg = f"{_join(path, str(key))}: not a setting Wicket reads here"
            close = difflib.get_close_matches(str(key), sorted(allowed), n=1)
            errors.append(msg + (f"; did you mean {close[0]}?" if close else ""))
    return out


def _join(path: str, name: str) -> str:
    return f"{path}.{name}" if path else name


def _section(raw, key: str, path: str, errors: list[str]):
    """raw[key] if it is a mapping; None if it is absent, or not a mapping (reported)."""
    if key not in raw:
        return None
    return _as_mapping(raw[key], _join(path, key), errors)


def _as_mapping(value, path: str, errors: list[str]):
    """`value` if it is a mapping; otherwise None, with the problem reported."""
    if isinstance(value, dict):
        return value
    errors.append(f"{path}: should be a mapping of settings, "
                  f"but YAML read it as {_describe(value)}")
    return None


def _named(raw, key: str, path: str, errors: list[str]):
    """(name, section, dotted path) for each entry of the mapping raw[key] --
    each user, each network.  An entry whose name is not text, or whose body is
    not a mapping, is reported and skipped."""
    group = _section(raw, key, path, errors)
    group_path = _join(path, key)
    for name, body in (group or {}).items():
        if not isinstance(name, str):
            errors.append(f"{group_path}: a name must be text, but YAML read one "
                          f"as {_describe(name)}{_quote_hint(name, str)}")
            continue
        body = _as_mapping(body, _join(group_path, name), errors)
        if body is not None:
            yield name, body, _join(group_path, name)


# --- Checking one value against a field's type ---------------------------------


@functools.cache
def _hints(cls) -> dict:
    return typing.get_type_hints(cls)


def _arms(hint) -> tuple:
    """The alternatives of a union type; a lone type is its own only alternative."""
    origin = typing.get_origin(hint)
    if origin is typing.Union or origin is types.UnionType:
        return typing.get_args(hint)
    return (hint,)


def _is_bool(value) -> bool:
    # ruamel loads an anchored boolean as ScalarBoolean, which subclasses int.
    return isinstance(value, (bool, ScalarBoolean))


def _matches(value, hint) -> bool:
    """Whether `value`, as YAML loaded it, is acceptable for a field annotated `hint`.

    A choice (Literal) matches in any case; _canonical gives its stored spelling.
    """
    arms = _arms(hint)
    if len(arms) > 1:
        return any(_matches(value, arm) for arm in arms)
    origin = typing.get_origin(hint)
    if hint is type(None):
        return value is None
    if hint is bool:
        return _is_bool(value)
    if hint is int:
        return isinstance(value, int) and not _is_bool(value)
    if hint is float:
        return isinstance(value, (int, float)) and not _is_bool(value)
    if hint is str:
        return isinstance(value, str)
    if origin is Literal:
        return isinstance(value, str) and value.lower() in (
            c.lower() for c in typing.get_args(hint))
    if origin is list:
        (item,) = typing.get_args(hint)
        return isinstance(value, list) and all(_matches(v, item) for v in value)
    if origin is dict:
        key, val = typing.get_args(hint)
        return isinstance(value, dict) and all(
            _matches(k, key) and _matches(v, val) for k, v in value.items())
    raise TypeError(f"no rule for checking a config value against {hint!r}")


def _canonical(value, hint):
    """`value`, with a choice spelled the way the schema spells it."""
    if isinstance(value, str):
        for arm in _arms(hint):
            if typing.get_origin(arm) is Literal:
                for choice in typing.get_args(arm):
                    if choice.lower() == value.lower():
                        return choice
    return value


def _check(value, hint, path: str, errors: list[str], secret: bool = False) -> bool:
    """Whether `value` fits `hint`; if not, report the innermost part that does not.

    A list or mapping of the right kind is looked into, so the message names
    the item that is wrong rather than the whole container.
    secret: the value is a password, so messages say what kind of value it is
        but never what it is.
    """
    if _matches(value, hint):
        return True
    container = next(
        (arm for arm in _arms(hint)
         if (typing.get_origin(arm) is list and isinstance(value, list))
         or (typing.get_origin(arm) is dict and isinstance(value, dict))),
        None)
    if container is None:
        errors.append(f"{path}: should be {_expected(hint)}, but YAML read it as "
                      f"{_describe(value, secret)}{_quote_hint(value, hint)}")
    elif typing.get_origin(container) is list:
        (item,) = typing.get_args(container)
        for i, v in enumerate(value):
            _check(v, item, f"{path}[{i}]", errors, secret)
    else:
        key_hint, val_hint = typing.get_args(container)
        for k, v in value.items():
            if not _matches(k, key_hint):
                errors.append(f"{path}: a key should be {_expected(key_hint)}, but YAML "
                              f"read one as {_describe(k)}{_quote_hint(k, key_hint)}")
            else:
                _check(v, val_hint, f"{path}.{k}", errors, secret)
    return False


def _quote_hint(value, hint) -> str:
    """Advice to quote, for a value YAML did not read as text where text would do."""
    if value is None or isinstance(value, str) or str not in _arms(hint):
        return ""
    return "; put it in quotes to keep it as text"


def _expected(hint) -> str:
    """`hint` in the words of someone editing the file."""
    arms = _arms(hint)
    text = " or ".join(_expected_one(a) for a in arms if a is not type(None))
    return text + " (or left empty)" if type(None) in arms else text


def _expected_one(hint) -> str:
    origin = typing.get_origin(hint)
    if origin is Literal:
        return "one of " + ", ".join(typing.get_args(hint))
    if origin is list:
        return "a list of " + _expected_inner(typing.get_args(hint)[0])
    if origin is dict:
        key, val = typing.get_args(hint)
        return f"a mapping of {_expected_inner(key)} to {_expected_inner(val)}"
    return {str: "text", int: "a whole number", float: "a number",
            bool: "true or false"}[hint]


def _expected_inner(hint) -> str:
    # Inside a list or mapping, an allowed None is not worth spelling out.
    return " or ".join(_expected_one(a) for a in _arms(hint) if a is not type(None))


def _describe(value, secret: bool = False) -> str:
    """What YAML made of `value`, in the words of someone editing the file.

    secret: say what kind of value it is, but not what it is.
    """
    if value is None:
        return "nothing (the key is empty)"
    if _is_bool(value):
        kind, shown = "a boolean", f"the boolean {str(bool(value)).lower()}"
    elif isinstance(value, (int, float)):
        kind, shown = "a number", f"the number {value}"
    elif isinstance(value, str):
        kind, shown = "text", f"the text {str(value)!r}"
    elif isinstance(value, datetime.date):  # datetime.datetime subclasses it
        kind, shown = "a date", f"the date {value}"
    elif isinstance(value, dict):
        noun = "key" if len(value) == 1 else "keys"
        kind = shown = "an empty mapping" if not value else "a mapping"
        if value:
            shown += f" with the {noun} " + ", ".join(repr(str(k)) for k in value)
    elif isinstance(value, list):
        kind = shown = ("an empty list" if not value else
                        f"a list of {len(value)} item{'' if len(value) == 1 else 's'}")
    else:
        kind = shown = type(value).__name__
    return kind if secret else shown


def _field_names(cls) -> set[str]:
    return {f.name for f in fields(cls)}


def _check_name_tables() -> None:
    """The tables above name fields by string; a misspelt or renamed entry would
    silently stop a setting cascading, or start echoing a secret.  Checked at
    import, so the mistake cannot survive the first run."""
    every = set().union(*(_field_names(c) for c in (
        BouncerConfig, UserConfig, NetworkConfig, ServerConfig, SASLConfig,
        ListenConfig, LoggingConfig, IdentConfig)))
    bad = [f"CASCADING has {n!r}" for n in sorted(CASCADING)
           if n not in _field_names(BouncerConfig) or n not in _field_names(UserConfig)]
    bad += [f"_SECRETS has {n!r}" for n in sorted(_SECRETS) if n not in every]
    bad += [f"_YAML_FORMS has {n!r}" for n in sorted(_YAML_FORMS)
            if n not in _field_names(NetworkConfig)]
    if bad:
        raise RuntimeError("config.py names fields that do not exist: " + "; ".join(bad))


_check_name_tables()
