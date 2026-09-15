"""Non-device adapter-v2 schema contract; never a production authority/provider.

Codec validation is not observation, signature provenance, or permission to run.
All inputs are detached bytes and all schema definitions are closed local data.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import json
import re
import unicodedata
from urllib.parse import quote_from_bytes, unquote_to_bytes
from types import MappingProxyType


class ContractError(ValueError):
    pass


PREFIX = "rtl-reader/native-page/adapter-v2/"
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_I64 = (1 << 63) - 1
MAX_U64 = (1 << 64) - 1
SIZE_CLASSES = MappingProxyType({
    "SMALL": 4096, "CONTROL": 65536, "LARGE": 1048576,
    "LARGE-SNAPSHOT": 2101761, "PROJECTION": 131072,
})
NON_WIRE_NAMES = frozenset({"CapabilityEngineV2", "ParentCapabilitySessionV2",
                            "ChildCapabilitySessionV2", "FridaProviderV2"})


def _reject(message: str) -> None:
    raise ContractError(message)


def _string(value: str) -> str:
    if type(value) is not str or "\x00" in value:
        _reject("not an exact non-NUL string")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        _reject("surrogate")
    if unicodedata.normalize("NFC", value) != value:
        _reject("non-NFC string")
    escaped = []
    for char in value:
        code = ord(char)
        if char == '"':
            escaped.append('\\"')
        elif char == "\\":
            escaped.append("\\\\")
        elif code < 32:
            escaped.append("\\u%04x" % code)
        else:
            escaped.append(char)
    return '"' + "".join(escaped) + '"'


def canonical(value: object) -> bytes:
    """The single exact codec. Object member ordering is ASCII byte ordering."""
    nodes = 0

    def emit(item: object, depth: int) -> str:
        nonlocal nodes
        nodes += 1
        if depth > 16 or nodes > 32768:
            _reject("canonical structural limit")
        if item is None:
            return "null"
        if type(item) is bool:
            return "true" if item else "false"
        if type(item) is int:
            if not -MAX_SAFE_INTEGER <= item <= MAX_SAFE_INTEGER:
                _reject("unsafe JSON integer")
            return str(item)
        if type(item) is str:
            return _string(item)
        if type(item) is list:
            return "[" + ",".join(emit(part, depth + 1) for part in item) + "]"
        if type(item) is dict:
            if any(type(key) is not str or not key.isascii() for key in item):
                _reject("non-ASCII/exact member name")
            nodes += len(item)
            if nodes > 32768:
                _reject("canonical member limit")
            return "{" + ",".join(_string(key) + ":" + emit(item[key], depth + 1)
                                  for key in sorted(item)) + "}"
        _reject("unsupported/subclass canonical value")

    return emit(value, 0).encode("utf-8")


def _preflight_json(raw: bytes, cap: int) -> str:
    if type(cap) is not int or cap < 1 or type(raw) is not bytes or not 1 <= len(raw) <= cap:
        _reject("exact bytes/encoded size")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise ContractError("invalid UTF-8") from error
    # Bound structures BEFORE json.loads can allocate an attacker-selected tree.
    inside = escaped = False
    depth = nodes = 0
    for char in text:
        if inside:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                inside = False
            continue
        if char == '"':
            inside = True
        elif char in "[{":
            depth += 1
            nodes += 1
            if depth > 17:
                _reject("preparse depth")
        elif char in "]}":
            depth -= 1
        elif char in ",:":
            nodes += 1
        if nodes > 32768:
            _reject("preparse nodes")
    return text


def decode_canonical(raw: bytes, cap: int = 65536) -> object:
    text = _preflight_json(raw, cap)

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                _reject("duplicate member")
            result[key] = value
        return result

    def no_number(_: str) -> object:
        _reject("float/nonfinite number")

    try:
        value = json.loads(text, object_pairs_hook=pairs,
                           parse_float=no_number, parse_constant=no_number)
    except (ValueError, RecursionError) as error:
        raise ContractError("invalid JSON") from error
    if canonical(value) != raw:
        _reject("noncanonical encoding")
    return value


def ld(domain: str, parts: tuple[bytes, ...]) -> bytes:
    if type(domain) is not str or not domain.isascii() or type(parts) is not tuple:
        _reject("LD argument type")
    encoded = domain.encode("ascii")
    if len(encoded) >= 1 << 32 or len(parts) >= 1 << 32:
        _reject("LD width")
    result = len(encoded).to_bytes(4, "big") + encoded + len(parts).to_bytes(4, "big")
    for part in parts:
        if type(part) is not bytes or len(part) >= 1 << 64:
            _reject("LD part type/width")
        result += len(part).to_bytes(8, "big") + part
    return result


@dataclass(frozen=True)
class Type:
    kind: str
    args: tuple = ()


def Const(value: object) -> Type:
    return Type("const", (value,))


def Enum(*values: str) -> Type:
    return Type("enum", tuple(values))


def Integer(low: int = 0, high: int = MAX_SAFE_INTEGER) -> Type:
    return Type("integer", (low, high))


def Decimal(low: int = 0, high: int = MAX_U64) -> Type:
    return Type("decimal", (low, high))


def Text(maximum: int = 128, grammar: str = "nfc") -> Type:
    return Type("text", (maximum, grammar))


def Ref(*targets: str) -> Type:
    return Type("ref", tuple(targets))


def Object(schema: str) -> Type:
    return Type("object", (schema,))


def Vector(member: Type, maximum: int, minimum: int = 0) -> Type:
    return Type("vector", (member, minimum, maximum))


def Tuple(*members: Type) -> Type:
    return Type("tuple", tuple(members))


def Nullable(member: Type) -> Type:
    return Type("nullable", (member,))


def Base64(decoded_bytes: int) -> Type:
    return Type("base64", (decoded_bytes,))


def SchemaName() -> Type:
    return Type("schema-name")


def Choice(*schemas: str) -> Type:
    """Closed tagged inline union: authority selects one exact registered body."""
    return Type("choice", tuple(schemas))


HASH = Type("hash")
BOOL = Type("boolean")
ID = HASH
U64 = Decimal()
HOST_TIME = Decimal(1, MAX_I64)
SIGNED_I64 = Decimal(-(1 << 63), MAX_I64)


@dataclass(frozen=True)
class Rule:
    """Closed data-only semantic rule; never an injected validation callback."""
    kind: str
    fields: tuple[str, ...]
    args: tuple = ()


@dataclass(frozen=True)
class Schema:
    name: str
    phase: str
    size_class: str
    fields: tuple[tuple[str, Type], ...]
    rules: tuple[Rule, ...] = ()
    envelope_bodies: tuple[str, ...] = ()
    key_role: str = "none"
    purposes: tuple[str, ...] = ("body-hash",)
    signature_profile: str = "none"


def _phase_fields(phase: str) -> tuple[tuple[str, Type], ...]:
    if phase == "S":
        return ()
    if phase == "N":
        return (("constructionId", ID),)
    if phase == "P":
        return (("planCoreSha256", Ref("PlanCoreV2")),)
    if phase == "E":
        return (("planCoreSha256", Ref("PlanCoreV2")),
                ("executionBindingSha256", Ref("ExecutionBindingBodyV2")))
    if phase == "X":
        return (("contextPhase", Enum("pre-plan", "pre-E", "post-E")),
                ("constructionId", ID),
                ("planCoreSha256", Nullable(Ref("PlanCoreV2"))),
                ("executionBindingSha256", Nullable(Ref("ExecutionBindingBodyV2"))))
    _reject("unknown phase")


def schema(name: str, phase: str, size_class: str,
           fields: dict[str, Type], *, rules: tuple[Rule, ...] = (),
           envelope_bodies: tuple[str, ...] = (), key_role: str = "none",
           purposes: tuple[str, ...] = ("body-hash",),
           signature_profile: str = "none") -> Schema:
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*V2", name) or name in NON_WIRE_NAMES:
        _reject("invalid wire name")
    if size_class not in SIZE_CLASSES:
        _reject("invalid size class")
    merged = {"authority": Const(PREFIX + "schema/" + name), "schemaVersion": Const(2)}
    for key, spec in _phase_fields(phase):
        merged[key] = spec
    for key, spec in fields.items():
        if key in merged and merged[key] != spec:
            _reject("conflicting common field: " + name + "." + key)
        merged[key] = spec
    return Schema(name, phase, size_class, tuple(sorted(merged.items())), rules,
                  envelope_bodies, key_role, purposes, signature_profile)


# Explicit definitions are appended below; there is no permissive fallback.
_DEFINITIONS: list[Schema] = []


def _add(item: Schema) -> None:
    if type(item) is not Schema or any(old.name == item.name for old in _DEFINITIONS):
        _reject("duplicate/nonexact schema")
    _DEFINITIONS.append(item)


def _validate_type(spec: Type, value: object, path: str, registry: dict) -> None:
    kind, args = spec.kind, spec.args
    if kind == "const":
        if type(value) is not type(args[0]) or value != args[0]:
            _reject(path + ": literal")
    elif kind == "enum":
        if type(value) is not str or value not in args:
            _reject(path + ": enum")
    elif kind == "integer":
        if type(value) is not int or not args[0] <= value <= args[1]:
            _reject(path + ": integer")
    elif kind == "decimal":
        if type(value) is not str or not re.fullmatch(r"0|-?[1-9][0-9]*", value):
            _reject(path + ": decimal grammar")
        if len(value) > 21 or not args[0] <= int(value) <= args[1]:
            _reject(path + ": decimal bound")
    elif kind == "schema-name":
        if type(value) is not str or value not in registry:
            _reject(path + ": named-unregistered body")
    elif kind in ("hash", "ref"):
        if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
            _reject(path + ": digest")
        if kind == "ref" and (not args or any(name not in registry for name in args)):
            _reject(path + ": unregistered reference target")
    elif kind == "boolean":
        if type(value) is not bool:
            _reject(path + ": boolean")
    elif kind == "base64":
        if type(value) is not str or not value.isascii():
            _reject(path + ": base64 type")
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as error:
            raise ContractError(path + ": base64") from error
        if len(decoded) != args[0] or base64.b64encode(decoded).decode("ascii") != value:
            _reject(path + ": base64 length/padding")
    elif kind == "text":
        if type(value) is not str or not 1 <= len(value.encode("utf-8")) <= args[0]:
            _reject(path + ": string bound")
        _string(value)
        grammar = args[1]
        if grammar == "token" and not re.fullmatch(r"[A-Za-z0-9_.:/-]+", value):
            _reject(path + ": token")
        if grammar == "ascii" and not value.isascii():
            _reject(path + ": ASCII")
        if grammar == "path":
            if not value.isascii() or not re.fullmatch(r"(?:[A-Z]:)?/(?:[A-Za-z0-9_. -]+/)*[A-Za-z0-9_. -]+", value):
                _reject(path + ": canonical path")
            if any(part in (".", "..") for part in value.split("/")):
                _reject(path + ": path dot component")
        if grammar == "uri":
            if not value.isascii() or not value.startswith("file:///"):
                _reject(path + ": URI")
            tail = value[7:]
            if not re.fullmatch(r"/(?:[A-Za-z0-9_.~-]|%[0-9A-F]{2}|/)+", tail):
                _reject(path + ": URI grammar")
            if any(part in (".", "..", "") for part in tail.split("/")[1:]):
                _reject(path + ": URI component")
            if re.search(r"%(?:00|2F|5C)", tail):
                _reject(path + ": URI encoded separator")
            try:
                decoded = unquote_to_bytes(tail).decode("utf-8", "strict")
            except UnicodeError as error:
                raise ContractError(path + ": URI UTF-8") from error
            _string(decoded)
            if any(part in (".", "..", "") for part in decoded.split("/")[1:]):
                _reject(path + ": decoded URI component")
            if quote_from_bytes(decoded.encode("utf-8"), safe="/-._~") != tail:
                _reject(path + ": noncanonical URI escape")
    elif kind == "object":
        _validate_value(args[0], value, registry)
    elif kind == "choice":
        if type(value) is not dict or type(value.get("authority")) is not str:
            _reject(path + ": tagged object")
        selected = value["authority"].removeprefix(PREFIX + "schema/")
        if selected not in args:
            _reject(path + ": union tag")
        _validate_value(selected, value, registry)
    elif kind == "vector":
        if type(value) is not list or not args[1] <= len(value) <= args[2]:
            _reject(path + ": vector")
        for index, item in enumerate(value):
            _validate_type(args[0], item, path + "/" + str(index), registry)
    elif kind == "tuple":
        if type(value) is not list or len(value) != len(args):
            _reject(path + ": tuple")
        for index, member in enumerate(args):
            _validate_type(member, value[index], path + "/" + str(index), registry)
    elif kind == "nullable":
        if value is not None:
            _validate_type(args[0], value, path, registry)
    else:
        _reject(path + ": unregistered primitive")


def _validate_value(name: str, value: object, registry: dict) -> None:
    if type(name) is not str or name not in registry:
        _reject("named-unregistered schema")
    spec = registry[name]
    if type(value) is not dict or set(value) != {key for key, _ in spec.fields}:
        _reject(name + ": exact keyset")
    for key, member in spec.fields:
        _validate_type(member, value[key], name + "/" + key, registry)
    if spec.phase == "X":
        phase, p, e = value["contextPhase"], value["planCoreSha256"], value["executionBindingSha256"]
        if ((phase == "pre-plan" and (p is not None or e is not None)) or
            (phase == "pre-E" and (p is None or e is not None)) or
            (phase == "post-E" and (p is None or e is None))):
            _reject(name + ": context mask")
    for rule in spec.rules:
        values = [value[field] for field in rule.fields]
        if rule.kind == "length":
            valid = values[0] == len(values[1])
        elif rule.kind == "equal":
            valid = all(type(item) is type(values[0]) and item == values[0] for item in values[1:])
        elif rule.kind == "unique":
            valid = len({canonical(item) for item in values[0]}) == len(values[0])
        elif rule.kind == "range":
            valid = values[0] <= values[1]
        elif rule.kind == "mask":
            discriminator, required, forbidden = rule.args
            valid = values[0] != discriminator or (all(value[k] is not None for k in required)
                    and all(value[k] is None for k in forbidden))
        elif rule.kind == "nullable-pair":
            valid = all((item is None) == (values[0] is None) for item in values[1:])
        elif rule.kind == "constant-if":
            valid = values[0] != rule.args[0] or values[1] == rule.args[1]
        elif rule.kind == "not-constant-if":
            valid = values[0] != rule.args[0] or values[1] != rule.args[1]
        elif rule.kind == "nonnull-constant":
            valid = values[0] is None or values[1] == rule.args[0]
        elif rule.kind == "envelope-body-field-equal":
            # This relation is intentionally evaluated only by reference_graph,
            # where the referenced authenticated envelope body is available.
            valid = True
        elif rule.kind == "ordered":
            valid = values[0] == sorted(values[0])
        elif rule.kind == "sum":
            valid = values[0] == values[1] + values[2]
        elif rule.kind == "reference-dispatch":
            valid = values[0] in dict(rule.args)
        elif rule.kind == "dispatch-schema-ref":
            allowed = dict(rule.args).get(values[0], ())
            valid = ((values[1] is None) == (values[2] is None) and
                     (values[1] is None or values[1] in allowed))
        elif rule.kind == "dispatch-ref":
            # The digest's concrete target is checked by reference_graph().
            # Body-only validation still closes the discriminator vocabulary.
            valid = values[0] in dict(rule.args) and values[1] is not None
        elif rule.kind == "dispatch-value":
            valid = (values[0] in dict(rule.args) and
                     (values[1] is None or values[1] == dict(rule.args)[values[0]]))
        elif rule.kind == "object-field-equal":
            valid = values[0] == values[1][rule.args[0]]
        elif rule.kind == "mask-in":
            discriminators, required, forbidden = rule.args
            valid = values[0] not in discriminators or (
                all(value[k] is not None for k in required) and
                all(value[k] is None for k in forbidden))
        elif rule.kind == "vector-range-if":
            discriminator, minimum, maximum = rule.args
            valid = values[0] != discriminator or minimum <= len(values[1]) <= maximum
        elif rule.kind == "numeric-range-if":
            discriminator, minimum, maximum = rule.args
            valid = values[0] != discriminator or minimum <= values[1] <= maximum
        elif rule.kind == "keyed-order":
            key_fields = rule.args[0]
            keys = [tuple(item[key] for key in key_fields) for item in values[0]]
            valid = len(set(keys)) == len(keys) and keys == sorted(keys)
        elif rule.kind == "keyed-complete":
            key_fields, expected = rule.args
            keys = tuple(tuple(item[key] for key in key_fields) for item in values[0])
            valid = keys == expected
        elif rule.kind == "contiguous-index":
            key, start = rule.args
            valid = tuple(item[key] for item in values[0]) == tuple(range(start, start + len(values[0])))
        elif rule.kind == "parallel-projection":
            key = rule.args[0]
            valid = values[1] == [item[key] for item in values[0]]
        elif rule.kind == "all-flag":
            key = rule.args[0]
            valid = values[1] is all(item[key] is True for item in values[0])
        elif rule.kind == "slot-token":
            valid = values[1] == AUTH_TOKENS[values[0]]
        elif rule.kind == "evidence-map":
            phase, map_kind, first_slot, last_slot, entries = values
            phase_start = 0 if phase == "before" else 12
            required_count = 11 if map_kind == "prior-seal" else 12
            if map_kind == "failed-prefix":
                expected_slots = tuple(range(phase_start, phase_start + len(entries)))
            else:
                expected_slots = tuple(range(phase_start, phase_start + required_count))
            actual_slots = tuple(item["slot"] for item in entries)
            valid = (actual_slots == expected_slots and
                     ((not entries and first_slot is None and last_slot is None) or
                      (bool(entries) and first_slot == actual_slots[0] and last_slot == actual_slots[-1])))
        elif rule.kind == "less":
            valid = int(values[0]) < int(values[1])
        elif rule.kind == "not-equal":
            valid = values[0] != values[1]
        elif rule.kind == "clock-xor":
            valid = (values[0] is None) != (values[1] is None)
        elif rule.kind == "advance-one":
            valid = int(values[1]) == int(values[0]) + 1
        elif rule.kind == "field-schema":
            valid = (values[1] is None and values[0] is None) or (
                type(values[1]) is dict and
                values[1].get("authority") == PREFIX + "schema/" + values[0])
        else:
            _reject("unregistered semantic rule")
        if not valid:
            _reject(name + ": semantic " + rule.kind)
    if len(canonical(value)) > SIZE_CLASSES[spec.size_class]:
        _reject(name + ": encoded class")


ALLOWED_TEXT_GRAMMARS = frozenset({"nfc","token","ascii","path","uri"})
ALLOWED_KEY_ROLES = frozenset({"none","supervisor-root","supervisor-P","supervisor-E",
    "outer-root","service-E","lane","transfer-terminal","transfer-ack","guardian-terminal",
    "guardian-control","ack-control","snapshot-control","lane-terminalization","exact-lane-or-service-bootstrap-control"})
ALLOWED_SIGNATURE_PROFILES = frozenset({"none","ed25519-P","ed25519-E","ed25519-N",
    "hmac-E","hmac-X","ed25519-X","hmac-settlement","hmac-guardian-hop","hmac-guardian-control","hmac-ack-control"})
ALLOWED_DOMAIN_PURPOSES = frozenset({"body-hash","envelope-hash","signature","mac",
    "key-id","session-id","hkdf-salt","hkdf-info","genesis","record-hash","frame-mac",
    "key-confirmation","aead-aad"})
SCHEMA_METADATA_MATRIX = frozenset(
    [("none","none",False,frozenset(p)) for p in (
      ("body-hash",),("body-hash","key-id"),("body-hash","session-id","key-id"),
      ("body-hash","hkdf-salt","hkdf-info","key-id"),
      ("body-hash","genesis","record-hash"),("body-hash","frame-mac"),
      ("body-hash","genesis","record-hash","frame-mac"),
      ("body-hash","key-confirmation"),("body-hash","aead-aad"))]
    + [("exact-lane-or-service-bootstrap-control","none",False,frozenset(("body-hash","frame-mac")))]
    + [(key,profile,True,frozenset(("envelope-hash","signature"))) for key,profile in (
      ("supervisor-root","ed25519-P"),("supervisor-P","ed25519-P"),
      ("supervisor-P","ed25519-E"),("supervisor-E","ed25519-E"),
      ("outer-root","ed25519-P"),("outer-root","ed25519-N"),("outer-root","ed25519-X"),("service-E","ed25519-E"))]
    + [(key,profile,True,frozenset(("envelope-hash","mac"))) for key,profile in (
      ("lane","hmac-E"),("transfer-terminal","hmac-E"),("transfer-ack","hmac-settlement"),
      ("guardian-terminal","hmac-guardian-hop"),("guardian-control","hmac-guardian-control"),
      ("ack-control","hmac-ack-control"),("snapshot-control","hmac-X"),
      ("lane-terminalization","hmac-E"))])


def _validate_type_definition(member, registry, owner, nested, referenced):
    if type(member) is not Type or type(member.kind) is not str or type(member.args) is not tuple:
        _reject("malformed member type in " + owner)
    kind,args=member.kind,member.args
    if kind=="const":
        if len(args)!=1 or type(args[0]) not in (type(None),bool,int,str):
            _reject("const type/arity")
        canonical(args[0])
    elif kind=="enum":
        if not args or any(type(x) is not str for x in args) or len(set(args))!=len(args):
            _reject("enum type/empty/duplicate")
        for x in args:
            _string(x)
    elif kind=="integer":
        if len(args)!=2 or any(type(x) is not int for x in args) or not -MAX_SAFE_INTEGER<=args[0]<=args[1]<=MAX_SAFE_INTEGER:
            _reject("integer descriptor")
    elif kind=="decimal":
        if len(args)!=2 or any(type(x) is not int for x in args) or not -(1<<63)<=args[0]<=args[1]<=MAX_U64:
            _reject("decimal descriptor")
    elif kind=="text":
        if len(args)!=2 or type(args[0]) is not int or not 1<=args[0]<=4194304 or type(args[1]) is not str or args[1] not in ALLOWED_TEXT_GRAMMARS:
            _reject("text descriptor")
    elif kind in ("hash","boolean","schema-name"):
        if args: _reject("scalar arity")
    elif kind=="base64":
        if len(args)!=1 or type(args[0]) is not int or not 1<=args[0]<=4096:
            _reject("base64 descriptor")
    elif kind in ("ref","object","choice"):
        if not args or (kind=="object" and len(args)!=1) or any(type(x) is not str or x not in registry for x in args) or len(set(args))!=len(args):
            _reject("reference descriptor in "+owner)
        referenced.update(args)
        if kind in ("object","choice"): nested.update(args)
    elif kind=="nullable":
        if len(args)!=1 or type(args[0]) is not Type or args[0].kind=="nullable":
            _reject("nullable descriptor")
        _validate_type_definition(args[0],registry,owner,nested,referenced)
    elif kind=="vector":
        if len(args)!=3 or type(args[1]) is not int or type(args[2]) is not int or not 0<=args[1]<=args[2]<=32767:
            _reject("vector descriptor")
        _validate_type_definition(args[0],registry,owner,nested,referenced)
    elif kind=="tuple":
        if len(args)>32767: _reject("tuple descriptor")
        for child in args: _validate_type_definition(child,registry,owner,nested,referenced)
    else: _reject("unknown primitive")
    # Detach every descriptor object from caller-owned mutable dataclass instances.
    return Type(kind,tuple(_clone_type(x) if type(x) is Type else x for x in args))


def _clone_type(member):
    return Type(member.kind,tuple(_clone_type(x) if type(x) is Type else x for x in member.args))


def _category(member):
    if member.kind=="nullable": return ("nullable",_category(member.args[0]))
    if member.kind=="const": return type(member.args[0])
    if member.kind in ("enum","decimal","text","hash","ref","base64","schema-name"): return str
    if member.kind=="integer": return int
    if member.kind=="boolean": return bool
    if member.kind in ("vector","tuple"): return list
    if member.kind in ("object","choice"): return dict
    _reject("category")


def _immutable(value):
    if type(value) in (type(None),bool,int,str): return True
    return type(value) is tuple and all(_immutable(x) for x in value)


def _validate_rule_definition(rule, fields, registry, owner):
    if type(rule) is not Rule or type(rule.kind) is not str or type(rule.fields) is not tuple or type(rule.args) is not tuple or not rule.fields or not _immutable(rule.args):
        _reject("malformed/mutable rule")
    if any(type(x) is not str or x not in fields for x in rule.fields) or len(set(rule.fields))!=len(rule.fields):
        _reject("rule fields")
    members=tuple(fields[x] for x in rule.fields); kind=rule.kind; args=rule.args
    signatures={"length":2,"unique":1,"range":2,"ordered":1,"sum":3,
        "less":2,"not-equal":2,"clock-xor":2,"advance-one":2,"field-schema":2}
    if kind in signatures:
        if len(members)!=signatures[kind] or args: _reject("rule arity")
        if kind=="length" and (members[0].kind!="integer" or members[1].kind not in ("vector","tuple","text")): _reject("length types")
        if kind in ("unique","ordered") and members[0].kind!="vector": _reject("vector rule type")
        if kind=="ordered" and members[0].args[0].kind not in ("enum","decimal","text","hash","ref","base64","integer"): _reject("ordered element")
        if kind in ("sum","range") and any(x.kind!="integer" for x in members): _reject("integer rule types")
        if kind in ("less","advance-one") and any(x.kind not in ("integer","decimal") for x in members): _reject("numeric rule types")
        if kind=="not-equal" and _category(members[0])!=_category(members[1]): _reject("comparison types")
        if kind=="clock-xor" and any(x.kind!="nullable" or x.args[0].kind!="decimal" for x in members): _reject("clock rule types")
        if kind=="field-schema":
            if members[0].kind!="enum" or members[1].kind not in ("object","choice") or set(members[0].args)!=set(members[1].args): _reject("field-schema types")
    elif kind=="equal":
        if len(members)<2 or args or len({_category(x) for x in members})!=1: _reject("equal signature")
    elif kind=="nullable-pair":
        if len(members)<2 or args or any(x.kind!="nullable" for x in members): _reject("nullable pair signature")
    elif kind=="mask":
        if len(members)!=1 or len(args)!=3: _reject("mask arity")
        discriminator,required,forbidden=args
        if type(required) is not tuple or type(forbidden) is not tuple or any(type(x) is not str or x not in fields for x in required+forbidden):
            _reject("mask fields")
        if len(set(required))!=len(required) or len(set(forbidden))!=len(forbidden) or set(required)&set(forbidden) or any(fields[x].kind!="nullable" for x in required+forbidden):
            _reject("mask nullable fields")
        _validate_type(members[0],discriminator,owner,registry)
    elif kind in ("constant-if","not-constant-if"):
        if len(members)!=2 or len(args)!=2: _reject("constant-if arity")
        for member,literal in zip(members,args):
            checked=member.args[0] if member.kind=="nullable" else member
            if checked.kind not in ("enum","const","integer","decimal","text","hash","ref","boolean","schema-name"):
                _reject("constant-if nonscalar")
            _validate_type(member,literal,owner,registry)
    elif kind=="nonnull-constant":
        if len(members)!=2 or len(args)!=1 or members[0].kind!="nullable":
            _reject("nonnull-constant arity")
        target=members[1].args[0] if members[1].kind=="nullable" else members[1]
        if target.kind not in ("enum","const","integer","decimal","text","hash","ref","boolean","schema-name"):
            _reject("nonnull-constant nonscalar")
        _validate_type(members[1],args[0],owner,registry)
    elif kind=="reference-dispatch":
        if len(members)!=1 or not args: _reject("reference-dispatch arity")
        if any(type(x) is not tuple or len(x)!=2 for x in args): _reject("dispatch table")
        for key,target in args:
            _validate_type(members[0],key,owner,registry)
            if type(target) is not str or target not in registry: _reject("dispatch target")
        if len({canonical(x[0]) for x in args})!=len(args): _reject("dispatch duplicate")
    elif kind in ("dispatch-schema-ref", "dispatch-ref", "dispatch-value"):
        expected_arity={"dispatch-schema-ref":3,"dispatch-ref":2,"dispatch-value":2}[kind]
        if len(members)!=expected_arity or not args: _reject(kind+" arity")
        if members[0].kind not in ("enum","const"): _reject(kind+" discriminator")
        if any(type(x) is not tuple or len(x)!=2 for x in args): _reject(kind+" table")
        keys=tuple(x[0] for x in args)
        if len(set(keys))!=len(keys): _reject(kind+" duplicate")
        for key,target in args:
            _validate_type(members[0],key,owner,registry)
            if kind=="dispatch-schema-ref":
                if members[1].kind not in ("enum","nullable") or members[2].kind not in ("ref","nullable"):
                    _reject("dispatch schema/ref types")
                targets=target
                if type(targets) is not tuple or not targets or any(type(x) is not str or x not in registry for x in targets):
                    _reject("dispatch schema targets")
                schema_member=members[1].args[0] if members[1].kind=="nullable" else members[1]
                ref_member=members[2].args[0] if members[2].kind=="nullable" else members[2]
                if schema_member.kind!="enum" or ref_member.kind!="ref" or not set(targets)<=set(schema_member.args) or not set(targets)<=set(ref_member.args):
                    _reject("dispatch schema/ref target types")
            elif kind=="dispatch-ref":
                ref_member=members[1].args[0] if members[1].kind=="nullable" else members[1]
                if ref_member.kind!="ref" or type(target) is not tuple or not target or not set(target)<=set(ref_member.args):
                    _reject("dispatch ref target types")
            else:
                _validate_type(members[1],target,owner,registry)
    elif kind=="object-field-equal":
        if len(members)!=2 or len(args)!=1 or members[1].kind!="object": _reject("object-field-equal arity")
        target=registry[members[1].args[0]]
        target_fields=dict(target.fields)
        if args[0] not in target_fields or _category(members[0])!=_category(target_fields[args[0]]):
            _reject("object-field-equal type")
    elif kind=="mask-in":
        if len(members)!=1 or len(args)!=3 or type(args[0]) is not tuple: _reject("mask-in arity")
        discriminators,required,forbidden=args
        if not discriminators or len(set(discriminators))!=len(discriminators): _reject("mask-in discriminators")
        for discriminator in discriminators: _validate_type(members[0],discriminator,owner,registry)
        if any(type(x) is not tuple for x in (required,forbidden)) or any(type(x) is not str or x not in fields for x in required+forbidden):
            _reject("mask-in fields")
        if set(required)&set(forbidden) or any(fields[x].kind!="nullable" for x in required+forbidden): _reject("mask-in nullable")
    elif kind in ("vector-range-if","numeric-range-if"):
        if len(members)!=2 or len(args)!=3: _reject(kind+" arity")
        _validate_type(members[0],args[0],owner,registry)
        if any(type(x) is not int for x in args[1:]) or not 0<=args[1]<=args[2]: _reject(kind+" bounds")
        if kind=="vector-range-if" and members[1].kind!="vector": _reject("vector-range-if type")
        if kind=="numeric-range-if" and members[1].kind!="integer": _reject("numeric-range-if type")
    elif kind in ("keyed-order","keyed-complete","contiguous-index"):
        if len(members)!=1 or members[0].kind!="vector" or members[0].args[0].kind not in ("object","choice"):
            _reject(kind+" vector")
        target=registry[members[0].args[0].args[0]]
        target_fields=dict(target.fields)
        if kind=="contiguous-index":
            if len(args)!=2 or args[0] not in target_fields or target_fields[args[0]].kind!="integer" or type(args[1]) is not int:
                _reject("contiguous-index args")
        else:
            if len(args)!=(2 if kind=="keyed-complete" else 1) or type(args[0]) is not tuple or not args[0]:
                _reject(kind+" args")
            if any(x not in target_fields or target_fields[x].kind in ("object","choice","vector","tuple","nullable") for x in args[0]):
                _reject(kind+" key")
            if kind=="keyed-complete":
                if type(args[1]) is not tuple or any(type(x) is not tuple or len(x)!=len(args[0]) for x in args[1]):
                    _reject("keyed-complete expected")
                for expected in args[1]:
                    for field_name,literal in zip(args[0],expected): _validate_type(target_fields[field_name],literal,owner,registry)
    elif kind=="parallel-projection":
        if len(members)!=2 or len(args)!=1 or members[0].kind!="vector" or members[0].args[0].kind!="object" or members[1].kind!="vector":
            _reject("parallel-projection args")
        target_fields=dict(registry[members[0].args[0].args[0]].fields)
        if args[0] not in target_fields or target_fields[args[0]]!=members[1].args[0]: _reject("parallel-projection type")
    elif kind=="all-flag":
        if len(members)!=2 or len(args)!=1 or members[0].kind!="vector" or members[0].args[0].kind!="object" or members[1].kind!="boolean":
            _reject("all-flag args")
        target_fields=dict(registry[members[0].args[0].args[0]].fields)
        if args[0] not in target_fields or target_fields[args[0]].kind!="boolean": _reject("all-flag type")
    elif kind=="slot-token":
        if len(members)!=2 or args or members[0].kind!="integer" or members[1].kind!="enum": _reject("slot-token args")
    elif kind=="evidence-map":
        if len(members)!=5 or args or members[0].kind!="enum" or members[1].kind!="enum" or any(x.kind!="nullable" for x in members[2:4]) or members[4].kind!="vector":
            _reject("evidence-map args")
    elif kind=="envelope-body-field-equal":
        if len(members)!=2 or len(args)!=3:
            _reject("envelope-body-field-equal arity")
        reference=members[0].args[0] if members[0].kind=="nullable" else members[0]
        envelope_name,body_name,body_field=args
        if (reference.kind!="ref" or envelope_name not in reference.args or
            type(envelope_name) is not str or envelope_name not in registry or
            type(body_name) is not str or body_name not in registry or
            type(body_field) is not str):
            _reject("envelope-body-field-equal targets")
        envelope=registry[envelope_name]
        body_fields=dict(registry[body_name].fields)
        if body_name not in envelope.envelope_bodies or body_field not in body_fields or _category(members[1])!=_category(body_fields[body_field]):
            _reject("envelope-body-field-equal type")
    else: _reject("unknown rule")
    return Rule(kind,tuple(rule.fields),tuple(rule.args))


def _dispatch_rule_fingerprint(rule):
    """Return the stable literal fingerprint of one body-dispatch rule."""
    if (type(rule) is not Rule or rule.kind!="dispatch-schema-ref" or
            rule.fields[1:]!=("bodySchema","bodySha256")):
        _reject("body-dispatch fingerprint input")
    encoded={"arms":[[discriminator,list(targets)]
                      for discriminator,targets in rule.args],
             "fields":list(rule.fields),"ruleKind":rule.kind}
    return hashlib.sha256(canonical(encoded)).hexdigest()


def compile_registry(definitions: tuple[Schema,...]) -> MappingProxyType:
    if type(definitions) is not tuple or not definitions: _reject("empty/nonexact registry")
    for policy in (ALLOWED_TEXT_GRAMMARS,ALLOWED_KEY_ROLES,ALLOWED_SIGNATURE_PROFILES,
                   ALLOWED_DOMAIN_PURPOSES,SCHEMA_METADATA_MATRIX):
        if type(policy) is not frozenset: _reject("mutable registry policy")
    registry={}
    for item in definitions:
        if type(item) is not Schema or type(item.name) is not str or not re.fullmatch(r"[A-Z][A-Za-z0-9]*V2",item.name) or item.name in NON_WIRE_NAMES or item.name in registry:
            _reject("invalid/duplicate schema")
        registry[item.name]=item
    result={}; edges={}; domains=set()
    for item in definitions:
        if type(item.phase) is not str or item.phase not in ("S","N","P","E","X"): _reject("invalid phase")
        if type(item.size_class) is not str or item.size_class not in SIZE_CLASSES: _reject("invalid class")
        if any(type(x) is not tuple for x in (item.fields,item.rules,item.envelope_bodies,item.purposes)): _reject("mutable schema containers")
        if any(type(x) is not tuple or len(x)!=2 for x in item.fields): _reject("field entry")
        keys=tuple(x[0] for x in item.fields)
        if any(type(x) is not str or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*",x) for x in keys) or len(set(keys))!=len(keys) or keys!=tuple(sorted(keys)):
            _reject("field names/order")
        nested=set(); referenced=set()
        fields={k:_validate_type_definition(v,registry,item.name,nested,referenced) for k,v in item.fields}
        required={"authority":Const(PREFIX+"schema/"+item.name),"schemaVersion":Const(2),**dict(_phase_fields(item.phase))}
        if any(fields.get(k)!=v for k,v in required.items()): _reject("common fields")
        for k in ("contextPhase","planCoreSha256","executionBindingSha256"):
            if k in fields and k not in required: _reject("phase-incompatible field")
        if item.phase=="S" and "constructionId" in fields: _reject("static construction ID")
        rules=tuple(_validate_rule_definition(x,fields,registry,item.name) for x in item.rules)
        exact_rule_contracts=globals().get("NAMED_EXACT_RULE_CONTRACTS",{})
        for expected_rule in exact_rule_contracts.get(item.name,()):
            same_slot=tuple(rule for rule in rules if
                rule.kind==expected_rule.kind and rule.fields==expected_rule.fields)
            if same_slot!=(expected_rule,):
                _reject("closed named semantic rule contract")
        expected_dispatch_fingerprints=globals().get("NAMED_BODY_DISPATCH_FINGERPRINTS",{})
        if item.name in expected_dispatch_fingerprints:
            body_dispatchers=tuple(rule for rule in rules if
                rule.kind=="dispatch-schema-ref" and
                rule.fields[1:]==("bodySchema","bodySha256"))
            if (len(body_dispatchers)!=1 or
                    _dispatch_rule_fingerprint(body_dispatchers[0])!=
                    expected_dispatch_fingerprints[item.name]):
                _reject("closed named body-dispatch fingerprint")
        bodies=item.envelope_bodies
        if any(type(x) is not str or x not in registry for x in bodies) or len(set(bodies))!=len(bodies) or bodies!=tuple(sorted(bodies)) or any(x not in referenced for x in bodies):
            _reject("envelope body set")
        purposes=item.purposes
        if not purposes or any(type(x) is not str or x not in ALLOWED_DOMAIN_PURPOSES for x in purposes) or len(set(purposes))!=len(purposes) or purposes!=tuple(sorted(purposes)): _reject("purpose set")
        if type(item.key_role) is not str or item.key_role not in ALLOWED_KEY_ROLES or type(item.signature_profile) is not str or item.signature_profile not in ALLOWED_SIGNATURE_PROFILES:
            _reject("key/profile")
        if (item.key_role,item.signature_profile,bool(bodies),frozenset(purposes)) not in SCHEMA_METADATA_MATRIX:
            _reject("key/profile/body/purpose matrix")
        if bodies:
            policy=globals().get("ENVELOPE_CONTRACTS")
            fingerprint=(item.phase,item.key_role,item.signature_profile,tuple(bodies),tuple(keys))
            if policy is not None and (item.name not in policy or policy[item.name]!=fingerprint):
                _reject("closed named envelope/key/body contract")
            if fields.get("bodySchema")!=Enum(*bodies) and not (len(bodies)==1 and fields.get("bodySchema")==Const(bodies[0])):
                _reject("envelope exact body tag")
            if fields.get("bodySha256")!=Ref(*bodies): _reject("envelope body reference")
            if item.signature_profile.startswith("ed25519"):
                if fields.get("signature")!=Base64(64) or fields.get("signatureAlgorithm")!=Const("Ed25519"): _reject("signature metadata")
                expected={"ed25519-P":"P","ed25519-E":"E","ed25519-N":"N","ed25519-X":"X"}[item.signature_profile]
                if item.phase!=expected: _reject("signature phase")
            else:
                if item.phase!=("X" if item.signature_profile=="hmac-X" else "E") or fields.get("tag")!=Base64(32) or fields.get("algorithm")!=Const("HMAC-SHA256"): _reject("MAC metadata")
        for purpose in purposes:
            value=PREFIX+item.name+"/"+purpose
            if value in domains: _reject("duplicate domain")
            domains.add(value)
        result[item.name]=Schema(item.name,item.phase,item.size_class,tuple(sorted(fields.items())),
            rules,tuple(bodies),item.key_role,tuple(purposes),item.signature_profile)
        edges[item.name]=tuple(sorted(nested))
    validate_dependency_dag(edges)
    return MappingProxyType(dict(sorted(result.items())))

def require_schema(name: str, registry: MappingProxyType) -> Schema:
    if type(name) is not str or name not in registry:
        _reject("named-unregistered schema")
    return registry[name]


def validate_body(name: str, raw: bytes, registry: MappingProxyType) -> dict:
    """Schema validation only; not authentication or a production admission API."""
    spec = require_schema(name, registry)
    value = decode_canonical(raw, SIZE_CLASSES[spec.size_class])
    _validate_value(name, value, registry)
    return value


def domain(name: str, purpose: str, registry: MappingProxyType) -> str:
    spec = require_schema(name, registry)
    if type(purpose) is not str or purpose not in spec.purposes:
        _reject("unregistered domain/purpose")
    return PREFIX + name + "/" + purpose


def body_digest(name: str, raw: bytes, registry: MappingProxyType) -> str:
    validate_body(name, raw, registry)
    return hashlib.sha256(ld(domain(name, "body-hash", registry), (raw,))).hexdigest()


def validate_dependency_dag(dependencies: dict[str,tuple[str,...]]) -> tuple[str,...]:
    if type(dependencies) is not dict: _reject("DAG type")
    if any(type(x) is not str for x in dependencies): _reject("DAG node type")
    normalized={}
    for node,parents in dependencies.items():
        if type(parents) is not tuple or any(type(x) is not str for x in parents):
            _reject("dependency shape")
        if len(set(parents))!=len(parents) or any(x not in dependencies for x in parents):
            _reject("dependency duplicate/unknown")
        normalized[node]=tuple(sorted(parents))
    active=set(); visited=set(); ordered=[]
    def visit(node):
        if node in active: _reject("dependency cycle")
        if node in visited: return
        active.add(node)
        for parent in normalized[node]: visit(parent)
        active.remove(node); visited.add(node); ordered.append(node)
    for node in sorted(normalized): visit(node)
    return tuple(ordered)

# Closed scalar vocabularies. Values are wire tokens, never callable names.
PHASE = Enum("before", "after")
LANE = Enum("authority", "frida")
FILE_ROLE = Enum("target-base-apk", "framework", "native-module-apk", "original-pdf", "mark")
HOP = Enum("AUTH_CHILD_TO_SERVICE", "FRIDA_CHILD_TO_SERVICE", "SERVICE_TO_SUPERVISOR", "SUPERVISOR_TO_VERIFIER")
TRANSCRIPT_KIND = Enum("activity-dump", "display-dump", "window-dump", "frida-callback", "detached-result")
CARRIER = Enum("inline", "bulk")
RECT = Tuple(Integer(0, 1872), Integer(0, 1872), Integer(1, 1872), Integer(1, 1872))
PATH = Text(1024, "path")
URI = Text(4096, "uri")
TOKEN = Text(128, "token")
PROCESS = Ref("ProcessIdentityV2")
OBJECT = Ref("WindowsObjectIdentityV2")
FAILURE = Nullable(Object("FirstFailureV2"))
SNAPSHOT = Object("AcquisitionSnapshotRefV2")
ROLE_VALUES = (
    "outer-owner", "verifier", "supervisor", "service", "authority-worker",
    "frida-worker", "stock-target", "pen-worker", "pen-guardian", "private-adb",
    "guardian-target-base-apk", "guardian-framework", "guardian-native-module-apk",
    "guardian-original-pdf", "guardian-mark", "callback-worker", "job", "control-send",
    "control-receive", "data-send", "data-receive", "payload-key", "ack-key",
    "terminal-key", "master-key", "signing-key", "output", "spool", "file-fd",
    "directory-fd",
)
_ACQUISITION_OWNERS = ("outer","verifier","supervisor","service","authority-child",
                       "frida-child","guardian","callback")
_ACQUISITION_ROLES = ("process","thread","job","signing-key","stream-key","payload-key",
    "ack-key","terminal-key","control-send","control-receive","data-send","data-receive",
    "file-fd","directory-fd","spool","store","gate","drain")
RESOURCE_ROLE = Enum(*(owner + ":" + role for owner in _ACQUISITION_OWNERS
                      for role in _ACQUISITION_ROLES))
RESOURCE_KIND = Enum("process", "thread", "job", "endpoint", "key", "fd",
                     "directory-fd", "spool", "store", "gate", "drain")
_ROLE_KIND_SUFFIX = {
    "process":"process", "thread":"thread", "job":"job",
    "signing-key":"key", "stream-key":"key", "payload-key":"key",
    "ack-key":"key", "terminal-key":"key", "control-send":"endpoint",
    "control-receive":"endpoint", "data-send":"endpoint", "data-receive":"endpoint",
    "file-fd":"fd", "directory-fd":"directory-fd", "spool":"spool",
    "store":"store", "gate":"gate", "drain":"drain",
}
RESOURCE_ROLE_KIND_TABLE = tuple(
    (owner+":"+role, _ROLE_KIND_SUFFIX[role])
    for owner in _ACQUISITION_OWNERS for role in _ACQUISITION_ROLES
)
CLOSURE_PROOF_KINDS = (
    "process-joined", "thread-closed", "job-empty-closed",
    "endpoint-send-closed", "endpoint-receive-eof-closed", "key-destroyed",
    "fd-closed", "directory-fd-closed", "spool-closed", "store-closed",
    "gate-closed", "drain-closed",
)
_ROLE_CLOSURE_SUFFIX = {
    "process":"process-joined", "thread":"thread-closed", "job":"job-empty-closed",
    "signing-key":"key-destroyed", "stream-key":"key-destroyed",
    "payload-key":"key-destroyed", "ack-key":"key-destroyed",
    "terminal-key":"key-destroyed", "control-send":"endpoint-send-closed",
    "data-send":"endpoint-send-closed", "control-receive":"endpoint-receive-eof-closed",
    "data-receive":"endpoint-receive-eof-closed", "file-fd":"fd-closed",
    "directory-fd":"directory-fd-closed", "spool":"spool-closed",
    "store":"store-closed", "gate":"gate-closed", "drain":"drain-closed",
}
RESOURCE_ROLE_CLOSURE_TABLE = tuple(
    (owner+":"+role, _ROLE_CLOSURE_SUFFIX[role])
    for owner in _ACQUISITION_OWNERS for role in _ACQUISITION_ROLES
)
RESOURCE_KIND_IDENTITY_TABLE = (
    ("process",("ProcessIdentityV2",)),
    ("thread",("WindowsObjectIdentityV2",)),
    ("job",("JobIdentityV2","WindowsObjectIdentityV2")),
    ("endpoint",("WindowsObjectIdentityV2","GuardianEndpointIdentityV2")),
    ("key",("WindowsObjectIdentityV2","AcquisitionTokenV2")),
    ("fd",("WindowsObjectIdentityV2","GuardianFdIncarnationV2")),
    ("directory-fd",("WindowsObjectIdentityV2","GuardianFdIncarnationV2")),
    ("spool",("WindowsObjectIdentityV2","SpoolIdentityV2")),
    ("store",("WindowsObjectIdentityV2",)),
    ("gate",("WindowsObjectIdentityV2",)),
    ("drain",("WindowsObjectIdentityV2",)),
)
FAILURE_CODES = (
    "invalid-schema", "invalid-identity", "invalid-provenance", "replay",
    "out-of-order", "deadline-expired", "clock-invalid", "not-created",
    "acquisition-uncertain", "bootstrap-invalid", "gate-unavailable",
    "peer-unavailable", "malformed-frame", "trailing-data", "hash-mismatch",
    "callback-failed", "callback-timeout", "callback-reentrancy", "closure-unproved",
    "publication-uncertain", "forbidden-operation", "internal-invariant",
)
LAYERS = ("construction", "authority", "frida", "guardian", "transcript", "service",
          "supervisor", "requester")
CONSTRUCTION_STEPS = ("CORE", "ROOT_KEY", "SERVICE_CREATE", "A_CREATE", "F_CREATE",
                      "ASSIGN", "SERVICE_KEY_BOOTSTRAP", "ENDPOINTS", "LANES",
                      "EXECUTION_BODY", "EXECUTION_SIGN", "EXECUTION_PUBLISH")
METHODS = ("admission", "assert_quiescent", "capture_stage_evidence", "attach",
           "load", "seal_callbacks", "unload", "detach", "teardown", "cancel",
           "fail_stop")
STEP_TOKENS = ("attach", "fresh-selector", "load", "callback-seal",
               "script-unload", "physical-detach", "operation-quiescence")
FACADES = ("authority", "frida-provider", "frida-session")
STATES = ("NEW", "ADMITTED", "BEFORE", "ATTACHED", "LOADED", "SEALED", "UNLOADED",
          "DETACHED", "AFTER", "CLOSED", "FAILED", "UNCERTAIN")
OUTCOME = Enum("proved", "uncertain")
HREFS = Vector(HASH, 16)


def _row(name, _phase="E", _size_class="SMALL", *, rules=(), key="none", purposes=("body-hash",),
         bodies=(), profile="none", **fields):
    _add(schema(name, _phase, _size_class, fields, rules=rules, key_role=key,
                purposes=tuple(sorted(purposes)), envelope_bodies=tuple(sorted(bodies)), signature_profile=profile))


_row("ProcessIdentityV2", "S", platform=Enum("windows", "android"),
     pid=Integer(1, 2147483647), processStartId=U64, bootId=ID, imageSha256=HASH,
     acquisitionAuthorityObservationSha256=Ref("AcquisitionAuthorityObservationV2"))
_row("TrustAnchorPinV2", "S", algorithm=Const("Ed25519"), publicKey=Base64(32),
     publicKeySha256=HASH, policyVersion=Integer(1, 2147483647),
     purposes=("body-hash", "key-id"))
_row("WindowsObjectIdentityV2", "X", objectKind=Enum("process", "thread", "job",
     "pipe-read", "pipe-write", "key", "store", "spool", "gate", "drain"),
     ownerPid=Integer(1, 2147483647), ownerProcessStartId=U64, nativeValue=U64,
     generation=ID, grantedRights=Vector(Enum("read","write","synchronize","query",
     "duplicate","terminate","assign","read-control"),8,1),
     inheritanceDisposition=Const("noninheritable"),
     sourceObjectIdentitySha256=Nullable(OBJECT), duplicateOrdinal=Integer(0, 511),
     duplicatedIntoPid=Nullable(Integer(1, 2147483647)),
     acquisitionAuthorityObservationSha256=Ref("AcquisitionAuthorityObservationV2"),
     rules=(Rule("nullable-pair", ("sourceObjectIdentitySha256", "duplicatedIntoPid")),))
_row("JobIdentityV2", "S", ownerProcessIdentity=PROCESS, objectIdentity=OBJECT,
     jobGeneration=ID, killOnLastClose=Const(True), assignmentPolicySha256=HASH)
_row("CodecFixtureV2", "S", a=Text(128), n=Integer(), z=BOOL)
_row("ExitObservationV2", "S", exitCode=Integer(0, 4294967295),
     signal=Nullable(Integer(1, 127)), joined=Const(True))
_row("JobMemberSetV2", "S", "CONTROL", members=Vector(PROCESS, 8),
     rules=(Rule("unique", ("members",)),))
_row("KeyDestructionObservationV2", "S", keyId=ID, generation=ID,
     destroyed=Const(True), remainingAliasCount=Const(0))
_row("OwnerActivityObservationV2", "S", activeOperationCount=Const(0),
     inFlightCallbackCount=Const(0), openTransferCount=Const(0),
     normalIngressSealed=Const(True))
_row("StreamEndObservationV2", "S", byteCount=U64,
     finalRecordSha256=Nullable(HASH), trailingByteCount=Const(0))
_row("SameFdObservationV2", "S",
     fdAcquisitionReceiptSha256=Ref("GuardianFdAcquisitionBodyV2"),
     beforeStatSha256=Ref("FileStatV2"), afterStatSha256=Ref("FileStatV2"),
     beforeOffset=U64, afterOffset=U64, sameGeneration=Const(True))
_row("PathResolutionObservationV2", "S", "CONTROL", canonicalPath=PATH,
     anchorIdentitySha256=Ref("GuardianFdIncarnationV2"),
     ancestorIdentities=Vector(Ref("GuardianFdIncarnationV2"), 32, 1),
     componentCount=Integer(1, 32), nofollow=Const(True), noXdev=Const(True),
     beneath=Const(True), finalStatSha256=Ref("FileStatV2"),
     rules=(Rule("length", ("componentCount", "ancestorIdentities")),))
_row("OrchestrationPolicyV2", "S", visualOnly=Const(True), retryAllowed=Const(False),
     brokerCount=Const(1), laneCount=Const(2), authoritySlotCount=Const(24),
     fridaCompositeCount=Const(1), requireExactClosure=Const(True),
     physicalOrder=Tuple(Const("before"), Const("frida"), Const("after")))
_row("TargetPolicyV2", "S", "CONTROL", serial=Text(128, "token"),
     package=Text(255, "token"), component=Text(512, "token"),
     allowedUid=Integer(0, 2147483647), documentUri=URI,
     selectedPageIndex=Integer(0, 2147483647), observerSourceSha256=HASH,
     requireNonzeroDisplay=Const(True), requireCausalAttach=Const(True),
     forbiddenOwnerRoles=Tuple(*(Const(x) for x in (
        "stock-target", "pen-worker", "pen-guardian", "private-adb", "service",
        "authority-worker", "frida-worker"))))
_row("HostPolicyV2", "S", package=Text(255, "token"),
     component=Text(512, "token"), packageSha256=HASH,
     canvas=Tuple(Const(1404), Const(1872)), densityDpi=Const(300), rotation=Const(0),
     stageIndex=Integer(0, 3), requestedRect=RECT, requireNonzeroDisplay=Const(True),
     requireRetainedGeneration=Const(True))
_row("PlanCoreV2", "S", "LARGE", serviceSessionId=ID, planNonce=ID,
     clockId=ID, createdMonotonicNs=HOST_TIME, operationDeadlineNs=HOST_TIME,
     cleanupGraceNs=Const("250000000"), cleanupDeadlineNs=HOST_TIME,
     supervisorTrustAnchor=Object("TrustAnchorPinV2"),
     outerOwnerTrustAnchor=Object("TrustAnchorPinV2"),
     outerOwnerImage=Object("ProcessImagePinV2"),
     supervisorImage=Object("ProcessImagePinV2"),
     serviceImage=Object("ProcessImagePinV2"),
     authorityWorkerImage=Object("WorkerImagePinV2"),
     fridaWorkerImage=Object("WorkerImagePinV2"),
     guardianImages=Vector(Object("GuardianImagePinV2"), 5, 5),
     authorityFactoryPolicySha256=HASH, fridaFactoryPolicySha256=HASH,
     targetPolicy=Object("TargetPolicyV2"), hostPolicy=Object("HostPolicyV2"),
     filePolicy=Object("FilePolicyV2"), observerSourceSha256=HASH,
     stabilityPolicySha256=Ref("StabilityPolicyV2"), limits=Object("AdapterLimitsV2"),
     orchestrationPolicy=Object("OrchestrationPolicyV2"),
     rules=(Rule("less", ("createdMonotonicNs", "operationDeadlineNs")),
            Rule("keyed-complete",("guardianImages",),
                 (("role",),tuple((x,) for x in FILE_ROLE.args)))))

_row("DependencyPinV2", "S", ordinal=Integer(0,127), canonicalPath=PATH, sha256=HASH,
     size=U64, fileIdentitySha256=HASH,
     loadDisposition=Enum("preloaded-only","retained-load-only"))
_row("AdapterLimitsV2","S",maxControlHeaderBytes=Const(4096),
     maxControlBodyBytes=Const(65536),maxTranscriptBytes=Const(4194304),
     maxTranscripts=Const(16),maxChunkBytes=Const(65536),maxPathBytes=Const(1024),
     maxUriBytes=Const(4096),maxDependencies=Const(128),maxAcquisitions=Const(512),
     maxGuardianFileBytes=Const(1073741824),guardianLeaseMs=Const(1000),
     callbackCountMax=Const(2),cleanupTotalNs=Const("250000000"),
     cleanupCallMaxNs=Const("25000000"))
_row("FileStatV2","S",device=U64,inode=U64,mode=U64,uid=U64,gid=U64,nlink=U64,
     size=U64,mtimeNs=SIGNED_I64,ctimeNs=SIGNED_I64,blocks=U64,blockSize=U64,
     statSerializationVersion=Const(2))
_row("ProcessImagePinV2","S","CONTROL",role=Enum("outer-owner","verifier","supervisor","service"),
     imagePath=PATH,imageSha256=HASH,fileIdentitySha256=HASH,dependencyManifestSha256=HASH,
     dependencies=Vector(Object("DependencyPinV2"),128),
     environmentPolicySha256=HASH,mitigationPolicySha256=HASH,
     rules=(Rule("keyed-order",("dependencies",),(("ordinal","canonicalPath"),)),
            Rule("contiguous-index",("dependencies",),("ordinal",0))))
_row("WorkerImagePinV2","S","LARGE",role=Enum("authority-worker","frida-worker"),
     factoryId=Enum("authority_worker-v2","frida_worker-v2"),imagePath=PATH,
     imageSha256=HASH,bootstrapSha256=HASH,interpreterSha256=HASH,
     dependencyManifestSha256=HASH,dependencies=Vector(Object("DependencyPinV2"),128),
     loadedDependencyClosureSha256=HASH,mitigationPolicySha256=HASH,environmentPolicySha256=HASH,
     rules=(Rule("keyed-order",("dependencies",),(("ordinal","canonicalPath"),)),
            Rule("contiguous-index",("dependencies",),("ordinal",0))))
_row("GuardianImagePinV2","S","CONTROL",role=FILE_ROLE,imagePath=PATH,imageSha256=HASH,
     dependencies=Vector(Object("DependencyPinV2"),128),dependencyManifestSha256=HASH,
     uid=Integer(0,2147483647),gid=Integer(0,2147483647),
     supplementaryGroups=Vector(Integer(0,2147483647),16),capabilityMask=U64,
     selinuxContext=Text(128,"token"),credentialPolicySha256=HASH,
     rules=(Rule("unique",("supplementaryGroups",)),Rule("ordered",("supplementaryGroups",)),
            Rule("keyed-order",("dependencies",),(("ordinal","canonicalPath"),)),
            Rule("contiguous-index",("dependencies",),("ordinal",0))))
_row("GuardianFilePolicyV2","S",role=FILE_ROLE,path=PATH,uri=URI,
     presencePolicy=Enum("required","observe-nullable"),reviewedContentSha256=Nullable(HASH),
     maxFileBytes=Decimal(0,1073741824),hardlinkCount=Const(1))
_row("FilePolicyV2","S","CONTROL",uriScheme=Const("file"),
     files=Vector(Object("GuardianFilePolicyV2"),5,5),
     maxTranscriptBytes=Const(4194304),rawDisclosureAllowed=Const(False),
     rules=(Rule("keyed-complete",("files",),
        (("role",),tuple((x,) for x in FILE_ROLE.args))),))
_row("GuardianEndpointIdentityV2","S",ownerProcessIdentitySha256=PROCESS,
     guardianSessionId=ID,deviceBootId=ID,nativeFd=U64,generation=ID,
     direction=Enum("send-only","receive-only"),device=U64,inode=U64,
     acquisitionAuthorityObservationSha256=Ref("AcquisitionAuthorityObservationV2"),
     noninheritable=Const(True))
_row("AcquisitionTokenV2","X",ownerKind=Enum("process","provisioned-root"),
     ownerIdentity=Nullable(PROCESS),ownerTrustAnchorSha256=Nullable(Ref("TrustAnchorPinV2")),
     resourceRole=RESOURCE_ROLE,acquisitionOrdinal=Integer(0,511),generation=ID,
     rules=(Rule("mask",("ownerKind",),("process",("ownerIdentity",),("ownerTrustAnchorSha256",))),
       Rule("mask",("ownerKind",),("provisioned-root",("ownerTrustAnchorSha256",),("ownerIdentity",))),
       Rule("constant-if",("ownerKind","resourceRole"),("provisioned-root","outer:process")),
       Rule("constant-if",("ownerKind","contextPhase"),("provisioned-root","pre-plan"))))
_row("AcquisitionReservationV2","X",ownerKind=Enum("process","provisioned-root"),
     tokenSha256=Ref("AcquisitionTokenV2"),expectedKind=RESOURCE_KIND,
     expectedRole=RESOURCE_ROLE,ownerIdentity=Nullable(PROCESS),absoluteDeadlineNs=HOST_TIME,
     rules=(Rule("mask",("ownerKind",),("process",("ownerIdentity",),())),
            Rule("mask",("ownerKind",),("provisioned-root",(),("ownerIdentity",))),
            Rule("dispatch-value",("expectedRole","expectedKind"),RESOURCE_ROLE_KIND_TABLE)))
_row("AcquisitionAuthorityObservationV2","X","CONTROL",
     reservationSha256=Ref("AcquisitionReservationV2"),tokenSha256=Ref("AcquisitionTokenV2"),
     observerKind=Enum("process","provisioned-root"),observerIdentity=Nullable(PROCESS),
     observerTrustAnchorSha256=Nullable(Ref("TrustAnchorPinV2")),observationNonce=ID,
     capturedMonotonicNs=HOST_TIME,outcome=Const("authorized"),
     rules=(Rule("mask",("observerKind",),("process",("observerIdentity",),("observerTrustAnchorSha256",))),
            Rule("mask",("observerKind",),("provisioned-root",("observerTrustAnchorSha256",),("observerIdentity",)))))
IDENTITY_SCHEMAS = ("ProcessIdentityV2","JobIdentityV2","WindowsObjectIdentityV2",
                    "GuardianEndpointIdentityV2","GuardianFdIncarnationV2",
                    "AcquisitionTokenV2","SpoolIdentityV2")
_row("AcquisitionResultV2","X",reservationSha256=Ref("AcquisitionReservationV2"),
     result=Enum("acquired","not-acquired","uncertain"),
     identitySchema=Nullable(Enum(*IDENTITY_SCHEMAS)),
     identitySha256=Nullable(Ref(*IDENTITY_SCHEMAS)),
     acquisitionReceiptSha256=Nullable(Ref("AcquisitionAuthorityObservationV2")),
     capturedMonotonicNs=HOST_TIME,
     rules=(Rule("mask",("result",),("acquired",("identitySchema","identitySha256","acquisitionReceiptSha256"),())),
            Rule("mask",("result",),("not-acquired",(),("identitySchema","identitySha256","acquisitionReceiptSha256"))),
            Rule("mask",("result",),("uncertain",(),("identitySchema","identitySha256"))),
            Rule("nullable-pair",("identitySchema","identitySha256")),
            Rule("dispatch-schema-ref",("result","identitySchema","identitySha256"),
                 (("acquired",IDENTITY_SCHEMAS),("not-acquired",IDENTITY_SCHEMAS),("uncertain",IDENTITY_SCHEMAS)))))
_row("FirstFailureV2","X",layer=Enum(*LAYERS),state=Enum(*CONSTRUCTION_STEPS,*STATES),
     operation=Nullable(Enum(*tuple(dict.fromkeys(METHODS+STEP_TOKENS+("construct","stream","cleanup","publish"))))),
     cursor=Integer(0,511),code=Enum(*FAILURE_CODES),evidenceSchema=Nullable(SchemaName()),
     evidenceSha256=Nullable(HASH),observedHostNs=HOST_TIME,retryable=Const(False),
     rules=(Rule("nullable-pair",("evidenceSchema","evidenceSha256")),))
_row("AcquisitionStateV2","X",resourceRole=RESOURCE_ROLE,acquisitionId=ID,
     acquisitionOrdinal=Integer(0,511),
     resourceKind=RESOURCE_KIND,state=Enum("not-created","created-closed","created-uncertain"),
     creationIntentSha256=Ref("AcquisitionReservationV2"),
     identitySchema=Nullable(Enum(*IDENTITY_SCHEMAS)),identitySha256=Nullable(Ref(*IDENTITY_SCHEMAS)),
     creationReceiptSha256=Nullable(Ref("AcquisitionResultV2")),
     closeReceiptSha256=Nullable(Ref("CloseReceiptV2","EndpointCloseReceiptV2")),
     joinReceiptSha256=Nullable(Ref("JoinReceiptV2")),
     jobEmptyReceiptSha256=Nullable(Ref("JobEmptyReceiptV2")),
     endpointEofReceiptSha256=Nullable(Ref("EndpointEofReceiptV2")),
     keyDestructionReceiptSha256=Nullable(Ref("KeyDestructionReceiptV2")),
     closureProofKind=Nullable(Enum(*CLOSURE_PROOF_KINDS)),
     observerReceiptSha256=Ref("PlatformObservationV2"),firstUncertainty=FAILURE,
     rules=(Rule("nullable-pair",("identitySchema","identitySha256")),
       Rule("nonnull-constant",("closureProofKind","state"),("created-closed",)),
       Rule("dispatch-value",("resourceRole","resourceKind"),RESOURCE_ROLE_KIND_TABLE),
       Rule("dispatch-schema-ref",("resourceKind","identitySchema","identitySha256"),RESOURCE_KIND_IDENTITY_TABLE),
       Rule("mask",("state",),("not-created",(),("identitySchema","identitySha256","creationReceiptSha256",
          "closeReceiptSha256","joinReceiptSha256","jobEmptyReceiptSha256","endpointEofReceiptSha256",
          "keyDestructionReceiptSha256","closureProofKind","firstUncertainty"))),
       Rule("mask",("state",),("created-closed",("identitySchema","identitySha256","creationReceiptSha256","closureProofKind"),("firstUncertainty",))),
       Rule("mask",("state",),("created-uncertain",("firstUncertainty",),("closureProofKind",))),
       Rule("dispatch-value",("resourceRole","closureProofKind"),RESOURCE_ROLE_CLOSURE_TABLE),
       Rule("mask",("closureProofKind",),("process-joined",("joinReceiptSha256",),("closeReceiptSha256","jobEmptyReceiptSha256","endpointEofReceiptSha256","keyDestructionReceiptSha256"))),
       Rule("mask",("closureProofKind",),("job-empty-closed",("closeReceiptSha256","jobEmptyReceiptSha256"),("joinReceiptSha256","endpointEofReceiptSha256","keyDestructionReceiptSha256"))),
       Rule("mask",("closureProofKind",),("endpoint-send-closed",("closeReceiptSha256",),("joinReceiptSha256","jobEmptyReceiptSha256","endpointEofReceiptSha256","keyDestructionReceiptSha256"))),
       Rule("mask",("closureProofKind",),("endpoint-receive-eof-closed",("closeReceiptSha256","endpointEofReceiptSha256"),("joinReceiptSha256","jobEmptyReceiptSha256","keyDestructionReceiptSha256"))),
       Rule("mask",("closureProofKind",),("key-destroyed",("keyDestructionReceiptSha256",),("closeReceiptSha256","joinReceiptSha256","jobEmptyReceiptSha256","endpointEofReceiptSha256"))),
       Rule("mask-in",("closureProofKind",),(tuple(x for x in CLOSURE_PROOF_KINDS if x.endswith("-closed") and not x.startswith(("job-","endpoint-"))),
          ("closeReceiptSha256",),("joinReceiptSha256","jobEmptyReceiptSha256","endpointEofReceiptSha256","keyDestructionReceiptSha256")))))
_row("AcquisitionSnapshotBodyV2","X","LARGE-SNAPSHOT",ownerIdentitySha256=PROCESS,
     sourceLedgerPrefixSha256=HASH,stateCount=Integer(0,512),
     states=Vector(Object("AcquisitionStateV2"),512),
     rules=(Rule("length",("stateCount","states")),
            Rule("keyed-order",("states",),(("acquisitionOrdinal","acquisitionId"),)),
            Rule("contiguous-index",("states",),("acquisitionOrdinal",0))))
_row("AcquisitionSnapshotRefV2","X",snapshotByteLength=Integer(1,2101761),
     snapshotSha256=Ref("AcquisitionSnapshotBodyV2"),stateCount=Integer(0,512),
     ownerIdentitySha256=PROCESS,sourceLedgerPrefixSha256=HASH)
_OBSERVATIONS = (
 ("CloseReceiptV2","handle-closed",("WindowsObjectIdentityV2","GuardianFdIncarnationV2"),None),
 ("EndpointHalfCloseReceiptV2","send-half-closed",("WindowsObjectIdentityV2",),None),
 ("EndpointEofReceiptV2","receive-eof-drained",("WindowsObjectIdentityV2",),"StreamEndObservationV2"),
 ("EndpointCloseReceiptV2","endpoint-closed",("WindowsObjectIdentityV2",),None),
 ("JoinReceiptV2","process-joined",("ProcessIdentityV2",),"ExitObservationV2"),
 ("JobEmptyReceiptV2","job-empty",("JobIdentityV2",),"JobMemberSetV2"),
 ("KeyDestructionReceiptV2","key-destroyed",("AcquisitionTokenV2",),"KeyDestructionObservationV2"),
 ("OwnerQuiescenceReceiptV2","owner-quiescent",("ProcessIdentityV2",),"OwnerActivityObservationV2"),
 ("PathResolutionReceiptV2","path-resolved",("GuardianFdIncarnationV2",),"PathResolutionObservationV2"),
 ("SameFdReceiptV2","same-fd",("GuardianFdIncarnationV2",),"SameFdObservationV2"),
)
for _name,_kind,_targets,_detail in _OBSERVATIONS:
    _row(_name,"X",reservationSha256=Ref("AcquisitionReservationV2"),
         subjectIdentitySchema=Enum(*_targets),subjectIdentitySha256=Ref(*_targets),
         observerIdentity=PROCESS,observerReceiptSha256=Nullable(Ref("PlatformObservationV2")),
         previousReceiptSha256=Nullable(Ref(*tuple(x[0] for x in _OBSERVATIONS))),
         observationKind=Const(_kind),capturedMonotonicNs=Nullable(HOST_TIME),
         capturedDeviceBoottimeMs=Nullable(HOST_TIME),result=OUTCOME,
         detailSha256=Nullable(Ref(_detail)) if _detail else Const(None),
         rules=(Rule("clock-xor",("capturedMonotonicNs","capturedDeviceBoottimeMs")),) +
               (Rule("mask",("result",),("proved",("observerReceiptSha256",),())),) +
               ((Rule("mask",("result",),("proved",("detailSha256",),())),) if _detail else ()))
_row("SpoolIdentityV2",ownerIdentity=PROCESS,objectIdentity=OBJECT,
     acquisitionTokenSha256=Ref("AcquisitionTokenV2"),generation=ID,maxBytes=Const(4194304),
     encrypted=Const(True),deleteOnClose=Const(True))
_row("PublicationUncertainReceiptV2","X",intendedSchema=Enum(
     "ServiceTerminalBodyV2","SupervisorClosureBodyV2","RequesterTerminalBodyV2",
     "ConstructionSettlementBodyV2","PrePlanAbortBodyV2"),
     intendedBodySha256=Nullable(HASH),lastDurableCheckpointSha256=HASH,
     reservedSlotId=ID,publicationReservationSha256=Ref("AcquisitionReservationV2"),
     publicationState=Enum("not-attempted","partial","acknowledgement-missing"),
     responsibleOwnerIdentity=PROCESS,outcome=Const("uncertain"))

FACTORY = Enum("authority_worker-v2","frida_worker-v2")
_row("LaneControlTransportV2","P","CONTROL",parentSend=OBJECT,childReceive=OBJECT,
     childSend=OBJECT,parentReceive=OBJECT,endpointPolicySha256=HASH)
_row("HopFactoryBindingV2","P",hopNamespace=HOP,senderProcessIdentity=PROCESS,
     receiverProcessIdentity=PROCESS,factoryGeneration=ID,hopMasterKeyId=ID,
     ackControlBindingSha256=Ref("AckControlFactoryBindingV2"),endpointPolicySha256=HASH,
     maxObjects=Const(16),maxObjectBytes=Const(4194304),purposes=("body-hash","key-id"))
_row("AckControlFactoryBindingV2","P",factoryId=ID,
     senderProcessIdentitySha256=PROCESS,receiverProcessIdentitySha256=PROCESS,
     senderControlSendIdentitySha256=OBJECT,receiverControlReceiveIdentitySha256=OBJECT,
     receiverControlSendIdentitySha256=OBJECT,senderControlReceiveIdentitySha256=OBJECT,
     masterKeyId=ID,generation=ID,endpointPolicySha256=HASH)
_row("LaneBindingBodyV2","P","CONTROL",serviceSessionId=ID,lane=LANE,factoryId=FACTORY,
     factoryPolicySha256=HASH,workerImageManifestSha256=Ref("WorkerImagePinV2"),
     laneNonce=ID,sessionId=ID,epochId=ID,epochAdmissionId=ID,keyId=ID,ownerIdentity=OBJECT,
     controlTransport=Object("LaneControlTransportV2"),callbackDrainIdentity=OBJECT,
     bulkTransport=Object("HopFactoryBindingV2"),resourceBindingSha256=HASH,
     operationCursorInitial=Const(0),messageOrdinalInitial=Const(0),bulkCursorInitial=Const(0),
     operationDeadlineNs=HOST_TIME,purposes=("body-hash","session-id","key-id"))
_row("SupervisorKeyAttestationBodyV2","P","CONTROL",supervisorProcessIdentity=PROCESS,
     supervisorImageSha256=Ref("ProcessImagePinV2"),trustAnchorPolicyVersion=Integer(1,2147483647),
     perRunKeyAlgorithm=Const("Ed25519"),perRunSigningPublicKey=Base64(32),
     perRunSigningKeyId=ID,createdMonotonicNs=HOST_TIME,purposes=("body-hash","key-id"))
_row("JobAssignmentReceiptV2","P",bindingStage=Const("pre-execution"),
     processRole=Enum("service","authority","frida"),processIdentity=PROCESS,
     jobIdentity=Ref("JobIdentityV2"),assignmentGeneration=ID,createdSuspended=Const(True),
     assignedBeforeResume=Const(True),activeJobProcessSetSha256=Ref("JobMemberSetV2"),
     capturedMonotonicNs=HOST_TIME,receiptOutcome=Enum("assigned","uncertain"))
_row("ServiceBootstrapResumeReceiptV2","P",constructionId=ID,serviceIdentity=PROCESS,
     jobAssignmentReceiptSha256=Ref("JobAssignmentReceiptV2"),bootstrapDescriptorSha256=HASH,
     resumeGeneration=ID,preSuspended=Const(True),authorityClass=Const("key-bootstrap-only"),
     authorizedHostNs=HOST_TIME,constructionDeadlineNs=HOST_TIME)
_row("ServiceBootstrapEffectReceiptV2","P",constructionId=ID,
     resumeAuthorizationSha256=Ref("ServiceBootstrapResumeReceiptV2"),serviceIdentity=PROCESS,
     resumeGeneration=ID,postState=Const("running-waiting-for-execution"),
     actualResumeHostNs=HOST_TIME,zeroNormalAuthorityHandleSetSha256=HASH,
     operationCount=Const(0),outcome=Enum("resumed","uncertain"))
_row("ServiceKeyBootstrapReceiptV2","P",
     serviceBootstrapEffectReceiptSha256=Ref("ServiceBootstrapEffectReceiptV2"),
     serviceImageSha256=Ref("ProcessImagePinV2"),serviceProcessIdentity=PROCESS,
     jobIdentity=Ref("JobIdentityV2"),zeroAuthorityHandleSetSha256=HASH,
     servicePublicKey=Base64(32),serviceKeyId=ID,signingHandleIdentitySha256=OBJECT,
     nonexportable=Const(True),executionGateIdentitySha256=OBJECT,
     outcome=Enum("bootstrap-waiting","uncertain"),purposes=("body-hash","key-id"))
_row("ExecutionBindingBodyV2","P","CONTROL",serviceSessionId=ID,
     authorityLaneBodySha256=Ref("LaneBindingBodyV2"),fridaLaneBodySha256=Ref("LaneBindingBodyV2"),
     supervisorKeyAttestationSha256=Ref("SupervisorKeyAttestationEnvelopeV2"),
     supervisorProcessIdentity=PROCESS,serviceProcessIdentity=PROCESS,serviceJobIdentity=Ref("JobIdentityV2"),
     serviceJobAssignmentReceiptSha256=Ref("JobAssignmentReceiptV2"),
     authorityWorkerAssignmentReceiptSha256=Ref("JobAssignmentReceiptV2"),
     fridaWorkerAssignmentReceiptSha256=Ref("JobAssignmentReceiptV2"),
     serviceKeyBootstrapReceiptSha256=Ref("ServiceKeyBootstrapReceiptV2"),
     outerControlBindingSha256=Ref("AckControlFactoryBindingV2"),
     serviceToSupervisorBulkBindingSha256=Ref("HopFactoryBindingV2"),
     supervisorToVerifierBulkBindingSha256=Ref("HopFactoryBindingV2"),
     serviceSigningAlgorithm=Const("Ed25519"),serviceSigningPublicKey=Base64(32),
     serviceSigningKeyId=ID,createdMonotonicNs=HOST_TIME)
_row("BootstrapResumeReceiptV2","E","CONTROL",processRole=LANE,processIdentity=PROCESS,
     jobAssignmentReceiptSha256=Ref("JobAssignmentReceiptV2"),descriptorSha256=HASH,
     bootstrapHandleSetSha256=HASH,resumeGeneration=ID,validationOnly=Const(True),
     workAuthorityGranted=Const(False),supervisorObservedNs=HOST_TIME,
     outcome=Enum("authorized","uncertain"))
_row("ProcessResumeReceiptV2",assignmentReceiptSha256=Ref("JobAssignmentReceiptV2"),
     bootstrapResumeAuthorizationSha256=Ref("BootstrapResumeReceiptV2"),processIdentity=PROCESS,
     jobIdentity=Ref("JobIdentityV2"),preSuspended=Const(True),postSuspended=BOOL,
     resumeGeneration=ID,capturedMonotonicNs=HOST_TIME,outcome=Enum("resumed-bootstrap-only","uncertain"))
_row("BootstrapValidationReceiptV2","E","CONTROL",laneBodySha256=Ref("LaneBindingBodyV2"),
     processRole=LANE,processIdentity=PROCESS,resumeReceiptSha256=Ref("ProcessResumeReceiptV2"),
     descriptorSha256=HASH,retainedBootstrapHandleSetSha256=HASH,validationChallenge=ID,
     validated=Const(True),normalWorkCount=Const(0),workGateConsumed=Const(False))
_row("ServiceExecutionValidationReceiptV2",serviceIdentity=PROCESS,
     serviceBootstrapEffectReceiptSha256=Ref("ServiceBootstrapEffectReceiptV2"),
     serviceKeyBootstrapReceiptSha256=Ref("ServiceKeyBootstrapReceiptV2"),
     executionDescriptorSha256=HASH,validationChallenge=ID,
     observedState=Const("running-waiting-for-work-gate"),normalWorkCount=Const(0),
     validated=Const(True),workGateConsumed=Const(False))
_row("WorkGateBodyV2","E","CONTROL",executionAttestationSha256=Ref("ExecutionAttestationEnvelopeV2"),
     validationReceiptDigests=Tuple(Ref("ServiceExecutionValidationReceiptV2"),
         Ref("BootstrapValidationReceiptV2"),Ref("BootstrapValidationReceiptV2")),
     gateId=ID,gateGeneration=ID,preGateRetainedHandleRootSha256=HASH,
     operationDeadlineNs=HOST_TIME,supervisorObservedNs=HOST_TIME,disposition=Const("open"))
_row("CapabilityBindingBodyV2","E","CONTROL",laneBodySha256=Ref("LaneBindingBodyV2"),
     factoryId=FACTORY,sessionId=ID,epochId=ID,workGateSha256=Ref("WorkGateBodyV2"),
     resourceBindingSha256=HASH,operationDeadlineNs=HOST_TIME)

_SLOT_SUFFIXES=("OPEN","DEVICE_STATE","TARGET_PROCESS","TARGET_BASE_APK","FRAMEWORK",
                "NATIVE_MODULE_APK","ORIGINAL_PDF","MARK","ACTIVITY","DISPLAY","WINDOW","SEAL")
AUTH_TOKENS=tuple("AUTH_SLOT_%02d_%s_%s"%(i+offset,phase,label)
    for offset,phase in ((0,"BEFORE"),(12,"AFTER")) for i,label in enumerate(_SLOT_SUFFIXES))
OPERATION_TOKEN=Enum(*AUTH_TOKENS,"FRIDA_PHYSICAL_COMPOSITE")
AUTHORITY_FAILURE_OPERATION=Enum(*AUTH_TOKENS,"FRIDA_PHYSICAL_COMPOSITE",
                                 "AUTHORITY_BARRIER","AUTHORITY_SNAPSHOT_CONTROL")
_row("OperationLeaseV2",capabilityBindingSha256=Ref("CapabilityBindingBodyV2"),
     operationId=ID,operationToken=OPERATION_TOKEN,cursor=Integer(0,24),
     absoluteDeadlineNs=HOST_TIME,startPermitNonce=ID,consumed=BOOL)
_row("DetachedPayloadV2",carrierTranscriptRefSha256=Ref("TranscriptRefV2"),
     payloadSchema=SchemaName(),payloadByteLength=Integer(1,65536),
     payloadSha256=HASH,operationReceiptSha256=Ref("CapabilityOperationReceiptV2"))
_row("DetachedBulkReferenceV2",transcriptRefSha256=Ref("TranscriptRefV2"),
     terminalEnvelopeSha256=Ref("BulkManifestEnvelopeV2"),
     operationReceiptSha256=Ref("CapabilityOperationReceiptV2"),canonicalByteLength=Integer(65537,4194304))
_row("CapabilityResultRefV2","E","CONTROL",kind=Enum("none","detached","transcript-set"),
     bodySchema=Nullable(SchemaName()),bodyByteLength=Integer(0,65536),bodySha256=Nullable(HASH),
     bulkRefCount=Integer(0,16),bulkRefDigests=Vector(Ref("DetachedBulkReferenceV2"),16),
     rules=(Rule("mask",("kind",),("none",(),("bodySchema","bodySha256"))),
       Rule("constant-if",("kind","bodyByteLength"),("none",0)),
       Rule("constant-if",("kind","bulkRefCount"),("none",0)),
       Rule("vector-range-if",("kind","bulkRefDigests"),("none",0,0)),
       Rule("mask",("kind",),("detached",("bodySchema","bodySha256"),())),
       Rule("numeric-range-if",("kind","bodyByteLength"),("detached",1,65536)),
       Rule("constant-if",("kind","bulkRefCount"),("detached",0)),
       Rule("vector-range-if",("kind","bulkRefDigests"),("detached",0,0)),
       Rule("mask",("kind",),("transcript-set",("bodySchema","bodySha256"),())),
       Rule("constant-if",("kind","bodySchema"),("transcript-set","TranscriptRefSetV2")),
       Rule("numeric-range-if",("kind","bodyByteLength"),("transcript-set",1,65536)),
       Rule("vector-range-if",("kind","bulkRefDigests"),("transcript-set",1,16)),
       Rule("length",("bulkRefCount","bulkRefDigests")),
       Rule("ordered",("bulkRefDigests",))))
_row("CapabilityOperationReceiptV2","E","CONTROL",laneBodySha256=Ref("LaneBindingBodyV2"),
     lane=LANE,factoryId=FACTORY,sessionId=ID,epochId=ID,operationId=ID,
     operationToken=OPERATION_TOKEN,operationCursorBefore=Integer(0,23),
     operationCursorAfter=Integer(1,24),brokerSlot=Nullable(Integer(0,23)),
     phase=Enum("before","after","none"),requestBodySha256=Ref("OperationLeaseV2"),
     previousOperationReceiptSha256=HASH,result=Object("CapabilityResultRefV2"),
     callbackCursorBefore=Integer(0,2),callbackCursorAfter=Integer(0,2),
     bulkCursorBefore=Integer(0,16),bulkCursorAfter=Integer(0,16),
     completedBulkRefDigests=Vector(Ref("DetachedBulkReferenceV2"),16),
     operationDeadlineNs=HOST_TIME,supervisorAcceptanceReceiptSha256=Ref("PlatformObservationV2"),
     outcome=Enum("success","failed","uncertain"),firstFailure=FAILURE,
     rules=(Rule("advance-one",("operationCursorBefore","operationCursorAfter")),
       Rule("mask",("outcome",),("success",(),("firstFailure",))),
       Rule("mask",("outcome",),("failed",("firstFailure",),())),
       Rule("mask",("outcome",),("uncertain",("firstFailure",),()))))
_row("AuthorityBarrierAcceptanceV2",authorityLaneBodySha256=Ref("LaneBindingBodyV2"),
     fridaLaneBodySha256=Ref("LaneBindingBodyV2"),authorityOperationCursorBefore=Const(12),
     authorityOperationCursorAfter=Const(12),brokerSlotCursor=Const(12),
     beforePhaseRootSha256=Ref("SlotEvidenceEnvelopeV2"),
     fridaPhysicalSettlementEnvelopeSha256=Ref("FridaPhysicalSettlementEnvelopeV2"),
     fridaOperationReceiptSha256=Ref("CapabilityOperationReceiptV2"),
     barrierRecordSha256=Ref("FridaBarrierRecordV2"),
     previousOperationReceiptSha256=Ref("CapabilityOperationReceiptV2"),
     supervisorAcceptanceReceiptSha256=Ref("PlatformObservationV2"),outcome=Const("accepted"))
_row("ActiveOperationCheckpointV2",laneBodySha256=Ref("LaneBindingBodyV2"),
     activeOperationId=ID,activeOperationCursor=Integer(0,23),completedOperationPrefixSha256=HASH,
     priorCallbacksDrained=Const(True),priorTransfersSettled=Const(True),
     activeOperationCount=Const(1),laneTerminal=Const(False))
_row("CapabilityTerminalizationRequestV2",laneBodySha256=Ref("LaneBindingBodyV2"),
     sessionId=ID,epochId=ID,requestId=ID,terminalizationCursor=Const(0),
     controlTransportSha256=Ref("LaneControlTransportV2"),terminalizationGeneration=ID,
     previousTerminalizationRecordSha256=HASH,
     lastOperationReceiptSha256=HASH,normalCursorFinal=Integer(0,24),
     requestToken=Enum("CAPV2_CLOSE_SUCCESS","CAPV2_REVOKE_FAILURE"),
     originalCleanupDeadlineNs=HOST_TIME,requesterIdentity=PROCESS,firstFailure=FAILURE,
     purposes=("body-hash","genesis","record-hash"),
     rules=(Rule("mask",("requestToken",),("CAPV2_CLOSE_SUCCESS",(),("firstFailure",))),
            Rule("mask",("requestToken",),("CAPV2_REVOKE_FAILURE",("firstFailure",),()))))
_row("CapabilityTerminalizationReceiptV2",requestSha256=Ref("CapabilityTerminalizationRequestV2"),
     laneBodySha256=Ref("LaneBindingBodyV2"),requestId=ID,terminalizationCursor=Const(1),
     winner=Enum("close","revoke","uncertain"),
     terminalEnvelopeSha256=Nullable(Ref("CapabilityTerminalEnvelopeV2")),
     quiescenceEnvelopeSha256=Nullable(Ref("CapabilityQuiescenceEnvelopeV2")),
     acquisitionSnapshotRef=SNAPSHOT,completedHostNs=HOST_TIME,firstFailure=FAILURE,
     rules=(Rule("mask",("winner",),("close",("terminalEnvelopeSha256","quiescenceEnvelopeSha256"),("firstFailure",))),
            Rule("mask",("winner",),("revoke",("terminalEnvelopeSha256","quiescenceEnvelopeSha256","firstFailure"),())),
            Rule("mask",("winner",),("uncertain",("firstFailure",),()))))
_row("CapabilityTerminalizationEnvelopeV2",bodies=("CapabilityTerminalizationRequestV2","CapabilityTerminalizationReceiptV2"),
     key="lane-terminalization",profile="hmac-E",purposes=("envelope-hash","mac"),
     bodySchema=Enum("CapabilityTerminalizationReceiptV2","CapabilityTerminalizationRequestV2"),
     bodyByteLength=Integer(1,65536),bodySha256=Ref("CapabilityTerminalizationReceiptV2","CapabilityTerminalizationRequestV2"),
     algorithm=Const("HMAC-SHA256"),keyId=ID,tag=Base64(32))
_row("CapabilityTerminalBodyV2","E","CONTROL",laneBodySha256=Ref("LaneBindingBodyV2"),
     lane=LANE,factoryId=FACTORY,sessionId=ID,epochId=ID,
     outcome=Enum("closed-success","closed-failure","closed-uncertain"),
     operationCursorFinal=Integer(0,24),messageOrdinalFinal=Integer(),bulkCursorFinal=Integer(0,16),
     lastOperationReceiptSha256=HASH,firstFailure=FAILURE,
     epochRevocationReceiptSha256=Ref("CapabilityTerminalizationRequestV2"),
     transportTerminalReceiptSha256=Ref("AckControlCloseBodyV2"),
     remainingEmitterStateSha256=Ref("RemainingEmitterStateV2"),terminal=Const(True),
     rules=(Rule("mask",("outcome",),("closed-success",(),("firstFailure",))),
       Rule("mask",("outcome",),("closed-failure",("firstFailure",),())),
       Rule("mask",("outcome",),("closed-uncertain",("firstFailure",),()))))
_row("CapabilityQuiescenceBodyV2","E","CONTROL",laneBodySha256=Ref("LaneBindingBodyV2"),
     sessionId=ID,terminalEnvelopeSha256=Ref("CapabilityTerminalEnvelopeV2"),
     activeOperationCount=Const(0),inFlightCallbackCount=Const(0),
     openBulkObjectCount=Const(0),openEndpointCount=Const(0),
     ownerQuiescenceSha256=Ref("OwnerQuiescenceReceiptV2"),
     transportQuiescenceSha256=Ref("EndpointCloseReceiptV2"),
     callbackDrainQuiescenceSha256=Ref("OwnerQuiescenceReceiptV2"),
     remainingEmitterStateSha256=Ref("RemainingEmitterStateV2"),checkedMonotonicNs=HOST_TIME,
     quiescent=Const(True))
_CONTROL_BODIES=("BootstrapValidationReceiptV2","ServiceExecutionValidationReceiptV2",
 "CapabilityOperationReceiptV2","AuthorityBarrierAcceptanceV2",
 "CapabilityTerminalizationEnvelopeV2",
 "DetachedPayloadV2","DetachedBulkReferenceV2")
_CONTROL_DISPATCH=(
 ("bootstrap-validation",("BootstrapValidationReceiptV2",)),
 ("service-validation",("ServiceExecutionValidationReceiptV2",)),
 ("operation",("CapabilityOperationReceiptV2",)),
 ("barrier",("AuthorityBarrierAcceptanceV2",)),
 ("terminalization",("CapabilityTerminalizationEnvelopeV2",)),
 ("detached",("DetachedPayloadV2",)),
 ("bulk-reference",("DetachedBulkReferenceV2",)),
)
_row("ControlEnvelopeV2",hopNamespace=HOP,direction=Enum("parent-to-child","child-to-parent"),
     messageSequence=Integer(),globalRecordOrdinal=Nullable(Integer()),
     kind=Enum("bootstrap-validation","service-validation","operation","barrier",
               "terminalization","detached","bulk-reference"),
     bodySchema=Enum(*_CONTROL_BODIES),bodyByteLength=Integer(1,65536),
     bodySha256=Ref(*_CONTROL_BODIES),previousEnvelopeRecordSha256=HASH,
     operationDeadlineNs=HOST_TIME,purposes=("body-hash","frame-mac"),
     key="exact-lane-or-service-bootstrap-control",
     rules=(Rule("dispatch-schema-ref",("kind","bodySchema","bodySha256"),_CONTROL_DISPATCH),))

_row("AckControlBindingV2",ackControlFactoryBindingSha256=Ref("AckControlFactoryBindingV2"),
     hopFactoryBindingSha256=Ref("HopFactoryBindingV2"),
     senderProcessIdentitySha256=PROCESS,receiverProcessIdentitySha256=PROCESS,
     generation=ID,normalSequenceInitial=Const(0),terminalSequenceInitial=Const(0),
     purposes=("body-hash","hkdf-salt","hkdf-info","key-id"))
_row("TranscriptReservationV2","E","CONTROL",transcriptIndex=Integer(0,15),
     transcriptId=ID,transcriptKind=TRANSCRIPT_KIND,sourceLane=LANE,reservationNonce=ID,state=Const("reserved"))
_row("EndpointOfferV2",hopFactoryBindingSha256=Ref("HopFactoryBindingV2"),
     reservationSha256=Ref("TranscriptReservationV2"),transferId=ID,offerNonce=ID,
     sendAcquisitionReceiptSha256=Ref("AcquisitionResultV2"),
     receiveAcquisitionReceiptSha256=Ref("AcquisitionResultV2"),
     duplicateReceiptSha256=Ref("AcquisitionResultV2"),
     senderProcessIdentity=PROCESS,receiverProcessIdentity=PROCESS,direction=Const("send-only"))
_row("EndpointAcceptV2",offerReceiptSha256=Ref("EndpointOfferV2"),transferId=ID,
     senderProcessIdentity=PROCESS,retainedDuplicateIdentitySha256=OBJECT,offerNonce=ID,accepted=Const(True))
_row("DataEndpointBindingV2",hopFactoryBindingSha256=Ref("HopFactoryBindingV2"),
     hopNamespace=HOP,reservationSha256=Ref("TranscriptReservationV2"),transferId=ID,
     senderIdentity=PROCESS,receiverIdentity=PROCESS,sendEndpointIdentity=OBJECT,
     receiveEndpointIdentity=OBJECT,offerReceiptSha256=Ref("EndpointOfferV2"),
     acceptReceiptSha256=Ref("EndpointAcceptV2"),creatorSendAliasCloseReceiptSha256=Ref("CloseReceiptV2"),
     duplicateLineageRootSha256=HASH,direction=Const("send-only"),keyGeneration=ID,
     purposes=("body-hash","hkdf-salt","hkdf-info","key-id"))
_row("EndpointFirstWriteGrantV2",dataEndpointBindingSha256=Ref("DataEndpointBindingV2"),
     transferId=ID,offerReceiptSha256=Ref("EndpointOfferV2"),
     acceptReceiptSha256=Ref("EndpointAcceptV2"),grantOrdinal=Const(0))
_TRANSFER_BASE=dict(hopNamespace=HOP,dataEndpointBindingSha256=Ref("DataEndpointBindingV2"),
 directionKeyId=ID,transcriptIndex=Integer(0,15),transcriptId=ID,transcriptKind=TRANSCRIPT_KIND)
_row("InlineTranscriptBodyV2",**_TRANSFER_BASE,canonicalByteLength=Integer(1,65536),
     transcriptSha256=HASH,hopRecordOrdinal=Integer(),previousRecordSha256=HASH,
     operationDeadlineNs=HOST_TIME,purposes=("body-hash","genesis","record-hash","frame-mac"))
_row("BulkChunkHeaderV2",**_TRANSFER_BASE,chunkIndex=Integer(0,63),offset=Integer(0,4194303),
     chunkBytes=Integer(1,65536),hopRecordOrdinal=Integer(),previousChunkRecordSha256=HASH,
     operationDeadlineNs=HOST_TIME,purposes=("body-hash","genesis","record-hash","frame-mac"))
_TRANSFER_CLOSE=dict(senderHalfCloseReceiptSha256=Ref("EndpointHalfCloseReceiptV2"),
 directionKeyDestructionReceiptSha256=Ref("KeyDestructionReceiptV2"),
 senderEndpointCloseReceiptSha256=Ref("EndpointCloseReceiptV2"),
 receiverEofReceiptSha256=Ref("EndpointEofReceiptV2"),
 receiverEndpointCloseReceiptSha256=Ref("EndpointCloseReceiptV2"),
 settlementAckSha256=Ref("SettlementAckEnvelopeV2"),
 canonicalEncoding=Const("utf8-canonical-json-v2"),terminal=Const(True))
_row("InlineTerminalBodyV2","E","CONTROL",**_TRANSFER_BASE,**_TRANSFER_CLOSE,
     canonicalByteLength=Integer(1,65536),transcriptSha256=HASH,
     inlineRecordSha256=Ref("InlineTranscriptBodyV2"))
_row("BulkManifestBodyV2","E","CONTROL",**_TRANSFER_BASE,**_TRANSFER_CLOSE,
     totalBytes=Integer(65537,4194304),chunkCount=Integer(2,64),transcriptSha256=HASH,
     genesisRecordSha256=HASH,finalChunkRecordSha256=HASH,firstHopRecordOrdinal=Integer(),
     lastHopRecordOrdinal=Integer())
_row("SettlementAckV2",dataEndpointBindingSha256=Ref("DataEndpointBindingV2"),
     transferId=ID,ackOrdinal=Const(0),carrier=CARRIER,transcriptSha256=HASH,
     totalBytes=Integer(1,4194304),finalPayloadRecordSha256=HASH,
     senderHalfCloseReceiptSha256=Ref("EndpointHalfCloseReceiptV2"),
     receiverEofReceiptSha256=Ref("EndpointEofReceiptV2"),
     receiverEndpointCloseReceiptSha256=Ref("EndpointCloseReceiptV2"),
     receiverCanonicalValidationSha256=Ref("PlatformObservationV2"),
     receiverPayloadKeyDestructionReceiptSha256=Ref("KeyDestructionReceiptV2"))
_row("AckControlCloseBodyV2","E","CONTROL",ackControlBindingSha256=Ref("AckControlBindingV2"),
     direction=Enum("sender-control","receiver-control"),lastNormalSequence=Integer(),
     lastTerminalSequence=Integer(),settledTransferRootSha256=HASH,
     pendingTransferSnapshotRef=Nullable(Ref("PendingTransferSnapshotV2")),
     normalIngressSealed=Const(True),remainingEmitterStateSha256=Ref("RemainingEmitterStateV2"),
     outcome=Enum("closed","uncertain"),terminal=Const(True))
_row("PendingTransferSnapshotV2","E","CONTROL",ackControlBindingSha256=Ref("AckControlBindingV2"),
     transferReservations=Vector(Ref("TranscriptReservationV2"),16),
     acquisitionSnapshotRef=SNAPSHOT,firstFailureSha256=Ref("FirstFailureV2"),outcome=Const("unresolved"),
     rules=(Rule("unique",("transferReservations",)),))

_TRANSCRIPT_SOURCE=dict(transcriptIndex=Integer(0,15),transcriptId=ID,
 transcriptKind=TRANSCRIPT_KIND,carrier=CARRIER,canonicalByteLength=Integer(1,4194304),
 transcriptSha256=HASH,sourceHopNamespace=Enum("AUTH_CHILD_TO_SERVICE","FRIDA_CHILD_TO_SERVICE"),
 sourceDataEndpointBindingSha256=Ref("DataEndpointBindingV2"),sourceDirectionKeyId=ID,
 sourceCarrierTerminalEnvelopeSha256=Ref("InlineTerminalEnvelopeV2","BulkManifestEnvelopeV2"),
 sourceHopFinalRecordSha256=HASH)
_CARRIER_TERMINAL_DISPATCH=(("inline",("InlineTerminalEnvelopeV2",)),
                            ("bulk",("BulkManifestEnvelopeV2",)))
_row("TranscriptAdmissionBodyV2","E","CONTROL",**_TRANSCRIPT_SOURCE,
     reservationSha256=Ref("TranscriptReservationV2"),
     rules=(Rule("dispatch-ref",("carrier","sourceCarrierTerminalEnvelopeSha256"),
                 _CARRIER_TERMINAL_DISPATCH),))
_row("TranscriptRefV2",**_TRANSCRIPT_SOURCE,admissionBodySha256=Ref("TranscriptAdmissionBodyV2"),
     serviceAdmissionRecordSha256=Ref("ServiceGlobalRecordV2"),
     rules=(Rule("dispatch-ref",("carrier","sourceCarrierTerminalEnvelopeSha256"),
                 _CARRIER_TERMINAL_DISPATCH),))
_row("TranscriptRefSetV2","E","CONTROL",refs=Vector(Object("TranscriptRefV2"),16),
     rules=(Rule("keyed-order",("refs",),(("transcriptIndex","transcriptId"),)),))
_row("TranscriptAbandonmentV2","E","CONTROL",reservationSha256=Ref("TranscriptReservationV2"),
     transcriptIndex=Integer(0,15),firstFailure=Object("FirstFailureV2"),
     acquisitionSnapshotRef=SNAPSHOT,outcome=Const("abandoned"),terminal=Const(True))
_row("TranscriptForwardReceiptV2",transcriptRefSha256=Ref("TranscriptRefV2"),
     routeIndex=Integer(1,2),hopNamespace=Enum("SERVICE_TO_SUPERVISOR","SUPERVISOR_TO_VERIFIER"),
     previousHopTerminalEnvelopeSha256=Ref("InlineTerminalEnvelopeV2","BulkManifestEnvelopeV2"),
     nextHopTerminalEnvelopeSha256=Ref("InlineTerminalEnvelopeV2","BulkManifestEnvelopeV2"),
     forwardedCanonicalByteLength=Integer(1,4194304),forwardedTranscriptSha256=HASH)
_row("TranscriptHopClosureV2","E","CONTROL",transcriptRefSha256=Nullable(Ref("TranscriptRefV2")),
     reservationSha256=Ref("TranscriptReservationV2"),routeIndex=Integer(0,2),hopNamespace=HOP,
     terminalEnvelopeSha256=Nullable(Ref("InlineTerminalEnvelopeV2","BulkManifestEnvelopeV2")),
     sendEndpointState=Object("AcquisitionStateV2"),receiveEndpointState=Object("AcquisitionStateV2"),
     payloadKeyState=Object("AcquisitionStateV2"),ackKeyState=Object("AcquisitionStateV2"),
     terminalKeyState=Object("AcquisitionStateV2"),masterKeyState=Object("AcquisitionStateV2"),
     spoolState=Object("AcquisitionStateV2"),independentObserverReceiptSha256=Ref("PlatformObservationV2"),
     outcome=Enum("closed","uncertain"))
GLOBAL_KINDS=("slot","transcript","barrier","frida-composite","authority-snapshot",
              "authority-failure","lane-closure","guardian-closure","transfer-closure",
              "cleanup-observation","success-seal")
GLOBAL_SCHEMAS=("SlotEvidenceEnvelopeV2","TranscriptAdmissionBodyV2","FridaBarrierRecordV2",
 "FridaCompositeReceiptV2","AuthoritySnapshotReceiptV2","AuthoritySnapshotFailureReceiptV2",
 "LaneClosureRefV2","GuardianClosureRefV2","TranscriptHopClosureV2","PlatformObservationV2",
 "SuccessSealV2")
_GLOBAL_DISPATCH=(
 ("slot",("SlotEvidenceEnvelopeV2",)),
 ("transcript",("TranscriptAdmissionBodyV2",)),
 ("barrier",("FridaBarrierRecordV2",)),
 ("frida-composite",("FridaCompositeReceiptV2",)),
 ("authority-snapshot",("AuthoritySnapshotReceiptV2",)),
 ("authority-failure",("AuthoritySnapshotFailureReceiptV2",)),
 ("lane-closure",("LaneClosureRefV2",)),
 ("guardian-closure",("GuardianClosureRefV2",)),
 ("transfer-closure",("TranscriptHopClosureV2",)),
 ("cleanup-observation",("PlatformObservationV2",)),
 ("success-seal",("SuccessSealV2",)),
)
_row("ServiceGlobalRecordV2","E","CONTROL",serviceSessionId=ID,globalRecordOrdinal=Integer(),
     recordKind=Enum(*GLOBAL_KINDS),semanticBodySchema=Enum(*GLOBAL_SCHEMAS),
     semanticBodySha256=Ref(*GLOBAL_SCHEMAS),transcriptIndex=Nullable(Integer(0,15)),
     previousServiceRecordSha256=HASH,acceptedMonotonicNs=HOST_TIME,
     purposes=("body-hash","record-hash","genesis"),
     rules=(Rule("dispatch-schema-ref",("recordKind","semanticBodySchema","semanticBodySha256"),
                 _GLOBAL_DISPATCH),
            Rule("mask",("recordKind",),("transcript",("transcriptIndex",),())),
            Rule("mask-in",("recordKind",),(tuple(x for x in GLOBAL_KINDS if x!="transcript"),
                 (),("transcriptIndex",)))))
_row("DeviceStateEvidenceV2",phase=PHASE,serial=Text(128,"token"),bootId=ID,
     firmwareFingerprint=Text(1024),deviceBoottimeMs=HOST_TIME,
     adbServerIdentitySha256=PROCESS,sourceCaptureReceiptSha256=Ref("PlatformObservationV2"),
     bodySha256=HASH)
_row("TargetProcessEvidenceV2","E","CONTROL",phase=PHASE,serial=Text(128,"token"),
     package=Text(255,"token"),component=Text(512,"token"),pid=Integer(1,2147483647),
     processStartId=U64,uid=Integer(0,2147483647),cmdlineSha256=HASH,
     processHandleIdentitySha256=Ref("ProcessIdentityV2"),
     sourceCaptureReceiptSha256=Ref("PlatformObservationV2"))
_row("PlacementSubjectV2","E","CONTROL",hostSessionId=ID,hostProcessIdentity=PROCESS,
     hostPackageSha256=HASH,taskId=Integer(1,2147483647),activityTokenSha256=HASH,
     displayId=Integer(1,2147483647),placementGeneration=ID,requestedRect=RECT,measuredRect=RECT,
     resumed=BOOL,visible=BOOL,measurementSha256=Ref("PlatformObservationV2"))
_row("PenLeaseSubjectV2",leaseIdSha256=HASH,serial=Text(128,"token"),guardianProcessIdentity=PROCESS,
     leaseSequence=Integer(),acquiredDeviceBoottimeMs=HOST_TIME,expiresDeviceBoottimeMs=HOST_TIME,
     inputBlocked=Const(True),providerReceiptSha256=Ref("PlatformObservationV2"),
     rules=(Rule("less",("acquiredDeviceBoottimeMs","expiresDeviceBoottimeMs")),))
_row("CheckpointSubjectV2",runSessionId=ID,checkpointSequence=Integer(),
     checkpointSha256=HASH,durabilityReceiptSha256=Ref("PlatformObservationV2"),storeIdentitySha256=OBJECT)
_row("ToolBundleSubjectV2","E","CONTROL",bundleId=ID,retainedRootIdentitySha256=OBJECT,
     manifestSha256=HASH,dependencies=Vector(Object("DependencyPinV2"),128),verifiedAll=Const(True),
     providerReceiptSha256=Ref("PlatformObservationV2"))
_row("PrivateAdbSubjectV2",serial=Text(128,"token"),serverProcessIdentity=PROCESS,
     serverPort=Integer(1,65535),socketIdentitySha256=OBJECT,bundleManifestSha256=HASH,
     sessionId=ID,providerReceiptSha256=Ref("PlatformObservationV2"))
_row("SelectorSubjectV2","E","CONTROL",serial=Text(128,"token"),package=Text(255,"token"),
     component=Text(512,"token"),pid=Integer(1,2147483647),processStartId=U64,
     uid=Integer(0,2147483647),fridaServerSessionId=ID,
     physicalAttachReceiptSha256=Ref("FridaPhysicalStepReceiptV2"),
     selectorCaptureSequence=Integer(),providerReceiptSha256=Ref("PlatformObservationV2"))
_row("LiveTargetBindingV2",targetPolicySha256=Ref("TargetPolicyV2"),processIdentity=PROCESS,
     taskId=Integer(1,2147483647),activityTokenSha256=HASH,displayId=Integer(1,2147483647),
     causalLaunchReceiptSha256=Ref("PlatformObservationV2"),
     causalAttachReceiptSha256=Ref("PlatformObservationV2"),forbiddenOwnerSetSha256=HASH,
     challenge=ID,capturedMonotonicNs=HOST_TIME,operationDeadlineNs=HOST_TIME)
_row("LiveHostBindingV2",hostPolicySha256=Ref("HostPolicyV2"),hostSessionId=ID,
     processIdentity=PROCESS,taskId=Integer(1,2147483647),activityTokenSha256=HASH,
     displayId=Integer(1,2147483647),placementGeneration=ID,packageSha256=HASH,
     placementReceiptSha256=Ref("PlatformObservationV2"),challenge=ID,
     capturedMonotonicNs=HOST_TIME,operationDeadlineNs=HOST_TIME)
_row("InitialFileObservationV2",filePolicySha256=Ref("FilePolicyV2"),fileRole=FILE_ROLE,
     presence=Enum("present","absent"),descriptorIdentitySha256=Nullable(Ref("GuardianFdIncarnationV2")),
     contentSha256=Nullable(HASH),absenceBeforeEvidenceSha256=Nullable(Ref("GuardianAbsenceBeforeEvidenceV2")),
     challenge=ID,capturedMonotonicNs=HOST_TIME,operationDeadlineNs=HOST_TIME,
     rules=(Rule("mask",("presence",),("present",("descriptorIdentitySha256","contentSha256"),("absenceBeforeEvidenceSha256",))),
       Rule("mask",("presence",),("absent",("absenceBeforeEvidenceSha256",),("descriptorIdentitySha256","contentSha256"))),
       Rule("constant-if",("presence","fileRole"),("absent","mark"))))
_row("PhaseOpenEvidenceV2","E","CONTROL",phase=PHASE,phaseChallenge=ID,
     placementAttestationSha256=Ref("SupervisorDetachedAttestationEnvelopeV2"),
     penAttestationSha256=Ref("SupervisorDetachedAttestationEnvelopeV2"),
     checkpointAttestationSha256=Ref("SupervisorDetachedAttestationEnvelopeV2"),
     toolBundleAttestationSha256=Ref("SupervisorDetachedAttestationEnvelopeV2"),
     privateAdbAttestationSha256=Ref("SupervisorDetachedAttestationEnvelopeV2"),
     hostProcessIdentitySha256=PROCESS,phasePredecessorRootSha256=Nullable(Ref("SlotEvidenceEnvelopeV2")),
     fridaPhysicalSettlementEnvelopeSha256=Nullable(Ref("FridaPhysicalSettlementEnvelopeV2")),
     fridaBarrierRecordSha256=Nullable(Ref("FridaBarrierRecordV2")),
     rules=(Rule("mask",("phase",),("before",(),("phasePredecessorRootSha256","fridaPhysicalSettlementEnvelopeSha256","fridaBarrierRecordSha256"))),
       Rule("mask",("phase",),("after",("phasePredecessorRootSha256","fridaPhysicalSettlementEnvelopeSha256","fridaBarrierRecordSha256"),()))))
_row("PhaseSealEvidenceV2","E","CONTROL",phase=PHASE,firstPriorSlot=Integer(0,12),
     lastPriorSlot=Integer(10,22),priorSlotRecordDigests=Vector(Ref("SlotEvidenceEnvelopeV2"),11,11),
     priorPhaseRootSha256=Nullable(Ref("SlotEvidenceEnvelopeV2")),evidenceMapSha256=Ref("EvidenceMapV2"),
     orderedTranscriptRefSha256=Ref("TranscriptRefSetV2"),stabilityProjectionSha256=Ref("StabilityResultV2"),
     fridaBarrierRecordSha256=Nullable(Ref("FridaBarrierRecordV2")),
     activeOperationCheckpointSha256=Ref("ActiveOperationCheckpointV2"),phaseOutcome=Const("sealed"),
     rules=(Rule("constant-if",("phase","firstPriorSlot"),("before",0)),
       Rule("constant-if",("phase","lastPriorSlot"),("before",10)),
       Rule("constant-if",("phase","firstPriorSlot"),("after",12)),
       Rule("constant-if",("phase","lastPriorSlot"),("after",22)),
       Rule("mask",("phase",),("before",(),("priorPhaseRootSha256","fridaBarrierRecordSha256"))),
       Rule("mask",("phase",),("after",("priorPhaseRootSha256","fridaBarrierRecordSha256"),()))))
_row("EvidenceMapEntryV2",slot=Integer(0,23),operationToken=Enum(*AUTH_TOKENS),
     payloadSchema=SchemaName(),payloadSha256=HASH,slotRecordSha256=Ref("SlotEvidenceEnvelopeV2"),
     rules=(Rule("slot-token",("slot","operationToken")),))
_row("EvidenceMapV2","E","CONTROL",phase=PHASE,mapKind=Enum("prior-seal","final-snapshot","failed-prefix"),
     firstSlot=Nullable(Integer(0,23)),lastSlot=Nullable(Integer(0,23)),
     orderedEntries=Vector(Object("EvidenceMapEntryV2"),12),
     rules=(Rule("nullable-pair",("firstSlot","lastSlot")),
            Rule("evidence-map",("phase","mapKind","firstSlot","lastSlot","orderedEntries"))))
_row("ParsedAuthorityV2","E","CONTROL",phase=PHASE,evidenceMapSha256=Ref("EvidenceMapV2"),
     targetPolicySha256=Ref("TargetPolicyV2"),hostPolicySha256=Ref("HostPolicyV2"),
     filePolicySha256=Ref("FilePolicyV2"),parsedTranscriptRefs=Vector(Object("TranscriptRefV2"),16),
     parserImageSha256=HASH,parserPolicySha256=HASH,accepted=Const(True),
     rules=(Rule("keyed-order",("parsedTranscriptRefs",),(("transcriptIndex","transcriptId"),)),))
_row("ParsedTranscriptEvidenceV2","E","CONTROL",phase=PHASE,
     transcriptKind=Enum("activity-dump","display-dump","window-dump"),
     transcriptRef=Ref("TranscriptRefV2"),parserImageSha256=HASH,parserPolicySha256=HASH,
     parsedAuthoritySha256=Ref("ParsedAuthorityV2"),parseReceiptSha256=Ref("PlatformObservationV2"),
     sourceCaptureReceiptSha256=Ref("PlatformObservationV2"))
STABLE_FIELDS=("serial","target-process","target-task","target-activity","host-process","host-task",
 "host-activity","host-apk","host-session","host-display","host-generation","private-adb","pen-lease",
 "observer","pdf-path","pdf-descriptor","pdf-content","mark-presence","mark-path","mark-descriptor",
 "mark-content","framework-descriptor","framework-content","module-descriptor","module-content",
 "raw-current-page","raw-page-info-page","raw-presenter-page")
_row("StabilityPolicyV2","S","CONTROL",policyId=Const("native-page-visual-fixed-v2"),
     comparedFields=Tuple(*(Const(x) for x in STABLE_FIELDS)),permittedDriftFields=Vector(TOKEN,0),
     requireSameRawPageTriplet=Const(True))
_row("StabilityComparisonV2",field=Enum(*STABLE_FIELDS),beforeValueSha256=HASH,
     afterValueSha256=HASH,equal=BOOL)
_row("StabilityResultV2","E","CONTROL",policySha256=Ref("StabilityPolicyV2"),
     beforeEvidenceMapSha256=Ref("EvidenceMapV2"),afterEvidenceMapSha256=Ref("EvidenceMapV2"),
     comparisons=Vector(Object("StabilityComparisonV2"),28,28),passed=BOOL,
     rules=(Rule("keyed-complete",("comparisons",),(("field",),tuple((x,) for x in STABLE_FIELDS))),
            Rule("all-flag",("comparisons","passed"),("equal",))))

_GSESSION=dict(guardianSessionId=ID,fileRole=FILE_ROLE,phase=PHASE,readEpoch=Integer(0,1))
_row("FileUriBindingV2","E","CONTROL",canonicalUriUtf8=URI,canonicalUriSha256=HASH,
     scheme=Const("file"),authorityEmpty=Const(True),queryAbsent=Const(True),
     fragmentAbsent=Const(True),decodedAbsolutePathUtf8=PATH,decodedPathSha256=HASH,
     pathResolutionReceiptSha256=Ref("PathResolutionReceiptV2"),descriptorDevice=U64,descriptorInode=U64)
_row("GuardianFdReservationBodyV2",guardianSessionId=ID,guardianProcessIdentitySha256=PROCESS,
     fileRole=FILE_ROLE,acquisitionId=ID,fdGeneration=ID,
     pathResolutionReceiptSha256=Ref("PathResolutionReceiptV2"),openFlags=U64,
     challenge=ID,state=Const("reserved"))
_row("GuardianFdAcquisitionBodyV2","E","CONTROL",
     reservationReceiptSha256=Ref("GuardianFdReservationBodyV2"),guardianSessionId=ID,
     acquisitionId=ID,fdNumber=Nullable(Integer(0,2147483647)),fdGeneration=ID,
     openFlags=Nullable(U64),initialStat=Nullable(Object("FileStatV2")),
     initialOffset=Nullable(U64),syscallSequence=Integer(),
     acquisitionOutcome=Enum("open-retained","open-failed","open-uncertain"),
     rules=(Rule("mask",("acquisitionOutcome",),("open-retained",("fdNumber","openFlags","initialStat","initialOffset"),())),
       Rule("mask",("acquisitionOutcome",),("open-failed",(),("fdNumber","openFlags","initialStat","initialOffset")))))
_row("GuardianFdIncarnationV2",guardianSessionId=ID,guardianProcessIdentitySha256=PROCESS,
     ownerPid=Integer(1,2147483647),ownerProcessStartId=U64,fdNumber=Integer(0,2147483647),
     fdGeneration=ID,fdAcquisitionReceiptSha256=Ref("GuardianFdAcquisitionBodyV2"),
     openFlags=U64,pathResolutionReceiptSha256=Ref("PathResolutionReceiptV2"),
     device=U64,inode=U64,fileType=Enum("regular","directory"),initialOffset=U64)
_row("GuardianTransportBindingV2","E","CONTROL",guardianSessionId=ID,
     guardianProcessIdentity=PROCESS,authorityChildIdentity=PROCESS,
     deviceTransportFactorySha256=HASH,hostRelayFactorySha256=HASH,rolePolicySha256=HASH,
     immutableOwnerBoundaryReceiptSha256=Ref("PlatformObservationV2"))
_row("GuardianProcessSubjectV2","E","CONTROL",guardianSessionId=ID,processIdentity=PROCESS,
     imagePinSha256=Ref("GuardianImagePinV2"),credentialPolicySha256=HASH,
     rolePolicySha256=HASH,bootId=ID,transportBindingSha256=Ref("GuardianTransportBindingV2"),challenge=ID)
_row("GuardianLeaseGrantV2",guardianSessionId=ID,guardianBootId=ID,offerChallenge=ID,
     offeredDeviceBoottimeMs=HOST_TIME,absoluteDeviceExpiryMs=HOST_TIME,leaseSequence=Integer(),
     workGateSha256=Ref("WorkGateBodyV2"),hostOperationDeadlineNs=HOST_TIME,supervisorIssuedNs=HOST_TIME,
     rules=(Rule("less",("offeredDeviceBoottimeMs","absoluteDeviceExpiryMs")),))
_row("ChildStreamKeyAttestationBodyV2",authorityLaneBodySha256=Ref("LaneBindingBodyV2"),
     childProcessIdentity=PROCESS,childImageManifestSha256=Ref("WorkerImagePinV2"),childSessionId=ID,
     guardianSessionId=ID,guardianProcessAttestationSha256=Ref("SupervisorDetachedAttestationEnvelopeV2"),
     guardianChallenge=ID,fileRole=FILE_ROLE,phase=PHASE,readEpoch=Integer(0,1),
     fdAcquisitionReceiptSha256=Ref("GuardianFdAcquisitionBodyV2"),
     childStreamPublicKey=Base64(32),keyId=ID,workGateSha256=Ref("WorkGateBodyV2"),
     supervisorObservedNs=HOST_TIME,operationDeadlineNs=HOST_TIME)
_row("GuardianStreamKeyAttestationBodyV2",authorityLaneBodySha256=Ref("LaneBindingBodyV2"),
     guardianProcessIdentity=PROCESS,guardianImageManifestSha256=Ref("GuardianImagePinV2"),
     guardianSessionId=ID,childProcessIdentity=PROCESS,childSessionId=ID,childChallenge=ID,
     fileRole=FILE_ROLE,phase=PHASE,readEpoch=Integer(0,1),
     fdAcquisitionReceiptSha256=Ref("GuardianFdAcquisitionBodyV2"),
     guardianStreamPublicKey=Base64(32),keyId=ID,workGateSha256=Ref("WorkGateBodyV2"),
     supervisorObservedNs=HOST_TIME,operationDeadlineNs=HOST_TIME)
_row("GuardianKeyContextV2",**_GSESSION,authorityLaneBodySha256=Ref("LaneBindingBodyV2"),
     childKeyAttestationSha256=Ref("ChildStreamKeyAttestationEnvelopeV2"),
     guardianKeyAttestationSha256=Ref("GuardianStreamKeyAttestationEnvelopeV2"),
     fdAcquisitionReceiptSha256=Ref("GuardianFdAcquisitionBodyV2"),childKeyId=ID,guardianKeyId=ID,
     purposes=("body-hash","hkdf-salt","hkdf-info","key-id"))
_row("GuardianKeyConfirmationV2",keyContextSha256=Ref("GuardianKeyContextV2"),
     authorRole=Enum("child","guardian"),challenge=ID,peerChallenge=ID,
     confirmationTag=Base64(32),purposes=("body-hash","key-confirmation"))
_row("GuardianChunkAadV2",keyContextSha256=Ref("GuardianKeyContextV2"),
     fdIncarnationSha256=Ref("GuardianFdIncarnationV2"),fileRole=FILE_ROLE,phase=PHASE,
     readEpoch=Integer(0,1),chunkIndex=Integer(0,16383),offset=Decimal(0,1073741823),
     plaintextLength=Integer(1,65536),previousChunkRecordSha256=HASH,
     purposes=("body-hash","aead-aad"))
_row("GuardianStreamChunkBodyV2",**_GSESSION,fdIncarnationSha256=Ref("GuardianFdIncarnationV2"),
     syscallSequence=Integer(),chunkIndex=Integer(0,16383),offset=Decimal(0,1073741823),
     plaintextLength=Integer(1,65536),ciphertextLength=Integer(1,65536),
     aeadNonce=Base64(12),aeadAadSha256=Ref("GuardianChunkAadV2"),
     ciphertextSha256=HASH,previousChunkRecordSha256=HASH,final=Const(False),
     purposes=("body-hash","genesis","record-hash"),
     rules=(Rule("equal",("plaintextLength","ciphertextLength")),))
_row("GuardianStreamReservationV2",**_GSESSION,
     hopNamespace=Enum("G_DEVICE_TO_SERVICE","SERVICE_TO_AUTHORITY"),
     guardianTransportBindingSha256=Ref("GuardianTransportBindingV2"),
     senderIdentitySha256=PROCESS,receiverIdentitySha256=PROCESS,
     reservationNonce=ID,generation=ID,hostOperationDeadlineNs=HOST_TIME)
_row("GuardianKeyChallengeV2",**_GSESSION,streamReservationSha256=Ref("GuardianStreamReservationV2"),
     authorRole=Enum("child","guardian"),peerIdentitySha256=PROCESS,challenge=ID,
     fdAcquisitionReceiptSha256=Ref("GuardianFdAcquisitionBodyV2"))
_row("GuardianStreamOfferV2",streamReservationSha256=Ref("GuardianStreamReservationV2"),
     offerNonce=ID,sendAcquisitionReceiptSha256=Ref("AcquisitionResultV2"),
     receiveAcquisitionReceiptSha256=Ref("AcquisitionResultV2"),duplicateReceiptSha256=Ref("AcquisitionResultV2"),
     senderIdentitySha256=PROCESS,receiverIdentitySha256=PROCESS)
_row("GuardianStreamAcceptV2",streamReservationSha256=Ref("GuardianStreamReservationV2"),
     offerReceiptSha256=Ref("GuardianStreamOfferV2"),offerNonce=ID,
     retainedSendIdentitySha256=Ref("WindowsObjectIdentityV2","GuardianEndpointIdentityV2"),
     senderIdentitySha256=PROCESS,accepted=Const(True))
_row("GuardianHopBindingV2",**_GSESSION,
     guardianTransportBindingSha256=Ref("GuardianTransportBindingV2"),
     hopNamespace=Enum("G_DEVICE_TO_SERVICE","SERVICE_TO_AUTHORITY"),
     senderIdentitySha256=PROCESS,receiverIdentitySha256=PROCESS,
     sendEndpointIdentitySha256=Ref("WindowsObjectIdentityV2","GuardianEndpointIdentityV2"),
     receiveEndpointIdentitySha256=Ref("WindowsObjectIdentityV2","GuardianEndpointIdentityV2"),
     offerReceiptSha256=Ref("GuardianStreamOfferV2"),acceptReceiptSha256=Ref("GuardianStreamAcceptV2"),
     creatorAliasCloseReceiptSha256=Ref("CloseReceiptV2"),
     controlBindingSha256=Ref("AckControlBindingV2"),masterKeyId=ID,generation=ID,
     purposes=("body-hash","hkdf-salt","hkdf-info","key-id"))
_row("GuardianStreamGrantV2",streamReservationSha256=Ref("GuardianStreamReservationV2"),
     hopBindingSha256=Ref("GuardianHopBindingV2"),offerReceiptSha256=Ref("GuardianStreamOfferV2"),
     acceptReceiptSha256=Ref("GuardianStreamAcceptV2"),creatorAliasCloseReceiptSha256=Ref("CloseReceiptV2"),
     grantOrdinal=Const(0),previousBootstrapControlSha256=Ref("GuardianControlEnvelopeV2"))
_row("GuardianControlKeySwitchV2",streamReservationSha256=Ref("GuardianStreamReservationV2"),
     hopBindingSha256=Ref("GuardianHopBindingV2"),
     previousBootstrapRecordSha256=Ref("GuardianControlEnvelopeV2"),
     keyContextSha256=Ref("GuardianKeyContextV2"),
     childConfirmationSha256=Ref("GuardianKeyConfirmationV2"),
     guardianConfirmationSha256=Ref("GuardianKeyConfirmationV2"),
     direction=Enum("sender-control","receiver-control"),generation=ID,derivedKeyId=ID,
     nextControlOrdinal=Integer(1,MAX_SAFE_INTEGER),switchOrdinal=Const(0))
_row("GuardianRelayHeaderV2",**_GSESSION,hopBindingSha256=Ref("GuardianHopBindingV2"),
     keyId=ID,frameOrdinal=Integer(0,16383),innerChunkIndex=Integer(0,16383),
     innerFrameByteLength=Integer(1,69656),innerFrameSha256=HASH,
     previousRelayRecordSha256=HASH,hostOperationDeadlineNs=HOST_TIME,
     purposes=("body-hash","genesis","record-hash","frame-mac"))
_row("GuardianHalfCloseV2",streamReservationSha256=Ref("GuardianStreamReservationV2"),
     hopBindingSha256=Ref("GuardianHopBindingV2"),frameCount=Integer(0,16384),
     totalInnerBytes=Decimal(0,1141243904),finalRelayRecordSha256=Nullable(HASH),
     halfCloseReceiptSha256=Ref("EndpointHalfCloseReceiptV2"))
_row("GuardianHopSettlementAckV2",hopBindingSha256=Ref("GuardianHopBindingV2"),
     guardianSessionId=ID,phase=PHASE,readEpoch=Integer(0,1),frameCount=Integer(0,16384),
     totalInnerBytes=Decimal(0,1141243904),finalRelayRecordSha256=Nullable(HASH),
     receiverEofReceiptSha256=Ref("EndpointEofReceiptV2"),
     receiverDataCloseReceiptSha256=Ref("EndpointCloseReceiptV2"),
     receiverPayloadKeyDestroyedReceiptSha256=Ref("KeyDestructionReceiptV2"),
     receiverValidationReceiptSha256=Ref("PlatformObservationV2"))
_row("GuardianHopTerminalBodyV2","E","CONTROL",hopBindingSha256=Ref("GuardianHopBindingV2"),
     guardianSessionId=ID,phase=PHASE,readEpoch=Integer(0,1),keyContextSha256=Ref("GuardianKeyContextV2"),
     childConfirmationSha256=Ref("GuardianKeyConfirmationV2"),
     guardianConfirmationSha256=Ref("GuardianKeyConfirmationV2"),frameCount=Integer(0,16384),
     totalInnerBytes=Decimal(0,1141243904),finalRelayRecordSha256=Nullable(HASH),
     settlementAckEnvelopeSha256=Nullable(Ref("GuardianControlEnvelopeV2")),
     senderHalfCloseReceiptSha256=Nullable(Ref("EndpointHalfCloseReceiptV2")),
     senderPayloadKeyDestroyedReceiptSha256=Nullable(Ref("KeyDestructionReceiptV2")),
     senderDataCloseReceiptSha256=Nullable(Ref("EndpointCloseReceiptV2")),
     acquisitionSnapshotRef=SNAPSHOT,outcome=Enum("closed","uncertain"),terminal=Const(True),
     rules=(Rule("mask",("outcome",),("closed",("settlementAckEnvelopeSha256",
        "senderHalfCloseReceiptSha256","senderPayloadKeyDestroyedReceiptSha256","senderDataCloseReceiptSha256"),())),))
_row("GuardianCancelV2",streamReservationSha256=Ref("GuardianStreamReservationV2"),
     guardianSessionId=ID,cancelSequence=Integer(),reason=Enum("deadline","peer-loss","first-failure"),
     firstFailureSha256=Ref("FirstFailureV2"),normalIngressSealed=Const(True))
_row("GuardianControlCloseV2",streamReservationSha256=Ref("GuardianStreamReservationV2"),
     hopBindingSha256=Nullable(Ref("GuardianHopBindingV2")),lastControlSequence=Integer(),
     lastControlRecordSha256=Ref("GuardianControlEnvelopeV2"),acquisitionSnapshotRef=SNAPSHOT,
     remainingEmitterStateSha256=Ref("RemainingEmitterStateV2"),outcome=Enum("closed","uncertain"),terminal=Const(True))
_row("GuardianOpenBodyV2","E","CONTROL",guardianSessionId=ID,fileRole=FILE_ROLE,
     guardianProcessAttestationSha256=Ref("SupervisorDetachedAttestationEnvelopeV2"),
     guardianRolePolicySha256=HASH,filePolicySha256=Ref("FilePolicyV2"),
     fileUriBinding=Nullable(Object("FileUriBindingV2")),fdIncarnation=Ref("GuardianFdIncarnationV2"),
     openStat=Object("FileStatV2"),expectedByteLength=Decimal(0,1073741824),
     childStreamPublicKey=Base64(32),guardianStreamPublicKey=Base64(32),
     keyAgreementBindingSha256=Ref("GuardianKeyContextV2"),readEpochInitial=Const(0),
     capturedDeviceBoottimeMs=HOST_TIME,outcome=Const("open"))
_row("GuardianAbsenceBodyV2",guardianSessionId=ID,fileRole=Const("mark"),phase=PHASE,
     directoryFdIncarnation=Ref("GuardianFdIncarnationV2"),sealedBasenameUtf8Sha256=HASH,
     lookupSequence=Integer(0,1),lookupReceiptSha256=Ref("GuardianSyscallReceiptV2"),
     directoryStat=Object("FileStatV2"),present=Const(False),
     previousAbsenceBodySha256=Nullable(Ref("GuardianAbsenceBodyV2")),outcome=Const("absent"))
for _name,_phase,_stat,_lookup in (
    ("GuardianAbsenceBeforeEvidenceV2","before","directoryStat","lookupBeforeReceiptSha256"),
    ("GuardianAbsenceAfterEvidenceV2","after","directoryStatAfter","lookupAfterReceiptSha256")):
    _fields=dict(phase=Const(_phase),fileRole=Const("mark"),guardianSessionId=ID,
         guardianProcessIdentitySha256=PROCESS,directoryFdIncarnationSha256=Ref("GuardianFdIncarnationV2"),
         entryNameUtf8Sha256=HASH,lookupEpoch=Const(0 if _phase=="before" else 1),
         present=Const(False),guardianEpochReceiptSha256=Ref("GuardianAbsenceBodyV2"))
    _fields[_stat]=Object("FileStatV2")
    _fields[_lookup]=Ref("GuardianSyscallReceiptV2")
    if _phase=="after":
        _fields["beforeAbsenceEvidenceSha256"]=Ref("GuardianAbsenceBeforeEvidenceV2")
    _row(_name,**_fields)
_row("GuardianFileDigestEvidenceV2","E","CONTROL",**_GSESSION,guardianProcessIdentitySha256=PROCESS,
     fdIncarnationSha256=Ref("GuardianFdIncarnationV2"),fileUriBinding=Nullable(Object("FileUriBindingV2")),
     statBefore=Object("FileStatV2"),expectedSize=Decimal(0,1073741824),
     streamedBytes=Decimal(0,1073741824),plaintextSha256=HASH,finalOffset=Decimal(0,1073741824),
     extraReadEof=Const(True),statAfter=Object("FileStatV2"),
     guardianOpenReceiptSha256=Ref("GuardianOpenBodyV2"),
     childStreamReceiptSha256=Ref("GuardianSyscallReceiptV2"),
     guardianEpochReceiptSha256=Ref("GuardianReadEpochTerminalBodyV2"),
     rules=(Rule("equal",("expectedSize","streamedBytes","finalOffset")),))

_GREAD_RECEIPTS=dict(seekSetReceiptSha256=Nullable(Ref("GuardianSyscallReceiptV2")),
 zeroByteEofReceiptSha256=Nullable(Ref("GuardianSyscallReceiptV2")),
 finalOffsetReceiptSha256=Nullable(Ref("GuardianSyscallReceiptV2")),
 pathToFdRevalidationReceiptSha256=Nullable(Ref("GuardianSyscallReceiptV2")),
 childDecryptCountHashReceiptSha256=Nullable(Ref("GuardianSyscallReceiptV2")),
 streamHalfCloseReceiptSha256=Nullable(Ref("EndpointHalfCloseReceiptV2")),
 streamEofReceiptSha256=Nullable(Ref("EndpointEofReceiptV2")),
 deviceHopTerminalEnvelopeSha256=Nullable(Ref("GuardianHopTerminalEnvelopeV2")),
 relayHopTerminalEnvelopeSha256=Nullable(Ref("GuardianHopTerminalEnvelopeV2")))
_row("GuardianReadEpochTerminalBodyV2","E","CONTROL",**_GSESSION,**_GREAD_RECEIPTS,
     fdIncarnationSha256=Ref("GuardianFdIncarnationV2"),statBefore=Nullable(Object("FileStatV2")),
     totalBytes=Decimal(0,1073741824),chunkCount=Integer(0,16384),plaintextSha256=HASH,
     firstChunkRecordSha256=Nullable(HASH),finalChunkRecordSha256=Nullable(HASH),
     statAfter=Nullable(Object("FileStatV2")),
     previousReadEpochTerminalSha256=Nullable(Ref("GuardianReadEpochTerminalBodyV2")),
     keyContextSha256=Ref("GuardianKeyContextV2"),childConfirmationSha256=Ref("GuardianKeyConfirmationV2"),
     guardianConfirmationSha256=Ref("GuardianKeyConfirmationV2"),sameFd=Const(True),terminal=Const(True),
     firstFailure=FAILURE,outcome=Enum("read-complete","read-failed","read-uncertain"),
     rules=(Rule("mask",("outcome",),("read-complete",tuple(_GREAD_RECEIPTS)+("statBefore","statAfter"),("firstFailure",))),
       Rule("mask",("outcome",),("read-failed",("firstFailure",),())),
       Rule("mask",("outcome",),("read-uncertain",("firstFailure",),())),
       Rule("mask",("phase",),("before",(),("previousReadEpochTerminalSha256",))),
       Rule("mask",("phase",),("after",("previousReadEpochTerminalSha256",),()))))
_GCLOSE_FIELDS=dict(fdAcquisitionReceiptSha256=Nullable(Ref("GuardianFdAcquisitionBodyV2")),
 guardianCloseBodySha256=Nullable(Ref("GuardianCloseBodyV2")),
 supervisorProcessClosureReceiptSha256=Nullable(Ref("GuardianProcessClosureReceiptV2")),
 missingLayerReceiptSha256=Nullable(Ref("MissingLayerTerminalBodyV2")))
_row("GuardianCloseBodyV2","E","CONTROL",guardianSessionId=ID,fileRole=FILE_ROLE,
     fdOrDirectoryIncarnationSha256=Ref("GuardianFdIncarnationV2"),
     lastReadOrAbsenceReceiptSha256=Ref("GuardianReadEpochTerminalBodyV2","GuardianAbsenceBodyV2"),
     fdCloseReceiptSha256=Ref("CloseReceiptV2"),
     allReadEpochKeysDestroyedReceiptSha256=Ref("KeyDestructionReceiptV2"),
     guardianPrivateKeyDestroyedReceiptSha256=Ref("KeyDestructionReceiptV2"),
     deviceSendEndpointCloseSha256=Ref("EndpointCloseReceiptV2"),
     exitIntentReceiptSha256=Ref("GuardianSyscallReceiptV2"),firstFailure=FAILURE,
     closeOutcome=Enum("closed","uncertain"),terminal=Const(True))
_row("GuardianProcessClosureReceiptV2",guardianSessionId=ID,guardianProcessIdentitySha256=PROCESS,
     guardianCloseBodySha256=Nullable(Ref("GuardianCloseBodyV2")),
     deviceTransportEofReceiptSha256=Nullable(Ref("EndpointEofReceiptV2")),
     processJoinReceiptSha256=Ref("JoinReceiptV2"),remainingHandleCloseSetSha256=HASH,
     stagingDeletionReceiptSha256=Ref("PlatformObservationV2"),outcome=Enum("proved-closed","uncertain"))
_row("GuardianClosureRefV2","E","CONTROL",**_GCLOSE_FIELDS,
     fileRole=FILE_ROLE,
     kind=Enum("normal","never-started","started-not-acquired","open-failed","open-uncertain","missing-crashed"),
     acquisitionSnapshotRef=SNAPSHOT,guardianAcquisitionState=Object("AcquisitionStateV2"),
     outcome=Enum("closed","uncertain"),
     rules=(Rule("mask",("kind",),("normal",("fdAcquisitionReceiptSha256","guardianCloseBodySha256","supervisorProcessClosureReceiptSha256"),("missingLayerReceiptSha256",))),
       Rule("mask",("kind",),("never-started",("supervisorProcessClosureReceiptSha256",),("fdAcquisitionReceiptSha256","guardianCloseBodySha256","missingLayerReceiptSha256"))),
       Rule("mask",("kind",),("started-not-acquired",("supervisorProcessClosureReceiptSha256",),("fdAcquisitionReceiptSha256","guardianCloseBodySha256","missingLayerReceiptSha256"))),
       Rule("mask",("kind",),("open-failed",("fdAcquisitionReceiptSha256","guardianCloseBodySha256","supervisorProcessClosureReceiptSha256"),("missingLayerReceiptSha256",))),
       Rule("mask",("kind",),("open-uncertain",("fdAcquisitionReceiptSha256","missingLayerReceiptSha256"),())),
       Rule("mask",("kind",),("missing-crashed",("missingLayerReceiptSha256",),("fdAcquisitionReceiptSha256","guardianCloseBodySha256","supervisorProcessClosureReceiptSha256"))),
       Rule("constant-if",("kind","outcome"),("normal","closed")),
       Rule("constant-if",("kind","outcome"),("never-started","closed")),
       Rule("constant-if",("kind","outcome"),("started-not-acquired","closed")),
       Rule("constant-if",("kind","outcome"),("open-failed","closed")),
       Rule("constant-if",("kind","outcome"),("open-uncertain","uncertain")),
       Rule("constant-if",("kind","outcome"),("missing-crashed","uncertain"))))
_row("GuardianSyscallReceiptV2",guardianSessionId=ID,
     incarnationSha256=Nullable(Ref("GuardianFdIncarnationV2")),
     reservationSha256=Ref("GuardianFdReservationBodyV2"),syscallSequence=Integer(),
     operation=Enum("seek-zero","stat","read-eof","offset","path-revalidate","decrypt-count-hash",
                    "fd-close","key-destroy","endpoint-close","staging-delete","exit-intent"),
     beforeOffset=Nullable(U64),afterOffset=Nullable(U64),byteCount=U64,rawDigest=Nullable(HASH),
     previousReceiptSha256=Nullable(Ref("GuardianSyscallReceiptV2")),
     capturedDeviceBoottimeMs=HOST_TIME,outcome=Enum("proved","failed","uncertain"))
_GCONTROL_KINDS=("key-challenge","child-key-attestation","guardian-key-attestation","key-confirmation",
 "stream-offer","stream-accept","stream-grant","key-switch","half-close","eof-ack",
 "stream-terminal","cancel","close","fd-reservation","fd-acquisition","open","read-terminal","absence","guardian-close","syscall")
_GCONTROL_TARGETS=("GuardianKeyChallengeV2","ChildStreamKeyAttestationEnvelopeV2",
 "GuardianStreamKeyAttestationEnvelopeV2","GuardianKeyConfirmationV2","GuardianStreamOfferV2",
 "GuardianStreamAcceptV2","GuardianStreamGrantV2","GuardianControlKeySwitchV2","GuardianHalfCloseV2",
 "GuardianHopSettlementAckV2","GuardianHopTerminalEnvelopeV2","GuardianCancelV2","GuardianControlCloseV2","GuardianFdReservationBodyV2",
 "GuardianFdAcquisitionBodyV2","GuardianOpenBodyV2","GuardianReadEpochTerminalBodyV2",
 "GuardianAbsenceBodyV2","GuardianCloseBodyV2","GuardianSyscallReceiptV2")
_GCONTROL_DISPATCH=tuple((kind,(target,)) for kind,target in zip(_GCONTROL_KINDS,_GCONTROL_TARGETS))
_row("GuardianControlBodyV2",**_GSESSION,streamReservationSha256=Ref("GuardianStreamReservationV2"),
     hopBindingSha256=Nullable(Ref("GuardianHopBindingV2")),controlSequence=Integer(),
     direction=Enum("sender-control","receiver-control"),controlClass=Enum("bootstrap","normal","terminalization"),
     previousControlRecordSha256=HASH,kind=Enum(*_GCONTROL_KINDS),payloadSchema=Enum(*_GCONTROL_TARGETS),
     payloadSha256=Ref(*_GCONTROL_TARGETS),payloadByteLength=Integer(1,65536),
     absoluteDeviceExpiryMs=HOST_TIME,hostOperationDeadlineNs=HOST_TIME,
     purposes=("body-hash","genesis","record-hash"),
     rules=(Rule("dispatch-schema-ref",("kind","payloadSchema","payloadSha256"),
                 _GCONTROL_DISPATCH),))

_row("PreAttachSelectorCommitV2","E","CONTROL",fridaLaneBodySha256=Ref("LaneBindingBodyV2"),
     liveTargetBindingSha256=Ref("LiveTargetBindingV2"),liveHostBindingSha256=Ref("LiveHostBindingV2"),
     targetPolicySha256=Ref("TargetPolicyV2"),targetProcessIdentitySha256=PROCESS,
     fridaServerProcessIdentitySha256=PROCESS,fridaServerSessionId=ID,observerSourceSha256=HASH,
     physicalOperationId=ID,selectorChallenge=ID,supervisorObservedNs=HOST_TIME,operationDeadlineNs=HOST_TIME)
_row("LogicalAttachBindingV2",fridaLaneBodySha256=Ref("LaneBindingBodyV2"),
     serial=Text(128,"token"),package=Text(255,"token"),component=Text(512,"token"),
     pid=Integer(1,2147483647),processStartId=U64,uid=Integer(0,2147483647),
     fridaServerSessionId=ID,observerSourceSha256=HASH,targetPolicySha256=Ref("TargetPolicyV2"),
     logicalAttachNonce=ID,physicalAttachReceiptSha256=Ref("FridaPhysicalStepReceiptV2"),
     freshSelectorAttestationSha256=Ref("SupervisorDetachedAttestationEnvelopeV2"),
     selectorChallenge=ID,physicalOperationId=ID,loadOperationId=ID,
     loadSourceByteLength=Integer(1,4194304),loadSourceSha256=HASH,stepCursorBeforeLoad=Const(2),
     previousPhysicalStepReceiptSha256=Ref("FridaPhysicalStepReceiptV2"),
     supervisorObservedNs=HOST_TIME,operationDeadlineNs=HOST_TIME)
_row("FridaStepResultV2",physicalOperationId=ID,stepOrdinal=Integer(0,6),stepToken=Enum(*STEP_TOKENS),
     targetIdentity=PROCESS,serverIdentity=PROCESS,sessionId=ID,scriptIdentity=Nullable(ID),
     callbackGeneration=ID,callbackCount=Integer(0,2),sourceImageSha256=HASH,
     handleCloseReceiptSha256=Nullable(Ref("CloseReceiptV2")),
     endpointCloseReceiptSha256=Nullable(Ref("EndpointCloseReceiptV2")),
     operationDeadlineNs=HOST_TIME,result=Enum("proved","failed","uncertain"))
_row("FridaPhysicalStepReceiptV2",fridaLaneBodySha256=Ref("LaneBindingBodyV2"),physicalOperationId=ID,
     stepCursorBefore=Integer(0,6),stepCursorAfter=Integer(1,7),stepToken=Enum(*STEP_TOKENS),
     stateBefore=Enum(*STATES),stateAfter=Enum(*STATES),previousStepReceiptSha256=HASH,
     startedMonotonicNs=HOST_TIME,completedMonotonicNs=HOST_TIME,
     resultBindingSha256=Nullable(Ref("FridaStepResultV2")),
     outcome=Enum("step-success","step-failure","step-uncertain"),firstFailure=FAILURE,
     rules=(Rule("advance-one",("stepCursorBefore","stepCursorAfter")),))
_row("FridaStepDispositionV2",ordinal=Integer(0,6),stepToken=Enum(*STEP_TOKENS),
     disposition=Enum("completed","failed","not-reached","cleanup-completed","cleanup-failed","cleanup-not-required"),
     stepReceiptSha256=Nullable(Ref("FridaPhysicalStepReceiptV2")),
     rules=tuple(Rule("mask",("disposition",),(x,("stepReceiptSha256",),())) for x in
        ("completed","failed","cleanup-completed","cleanup-failed"))+
        tuple(Rule("mask",("disposition",),(x,(),("stepReceiptSha256",))) for x in
        ("not-reached","cleanup-not-required")))
_row("FridaCallbackRecordV2",fridaLaneBodySha256=Ref("LaneBindingBodyV2"),physicalOperationId=ID,
     callbackOrdinal=Integer(0,1),callbackKind=Enum("snapshot","success-terminal","failure","failure-terminal"),
     callbackTranscriptRef=Ref("TranscriptRefV2"),observerResultCode=Enum("success",*FAILURE_CODES),
     previousCallbackRecordSha256=HASH,capturedMonotonicNs=HOST_TIME,terminal=BOOL)
_FRIDA_PREFIX=dict(logicalAttachBindingSha256=Nullable(Ref("LogicalAttachBindingV2")),
 physicalAttachReceiptSha256=Nullable(Ref("FridaPhysicalStepReceiptV2")),
 freshSelectorAttestationSha256=Nullable(Ref("SupervisorDetachedAttestationEnvelopeV2")),
 scriptLoadReceiptSha256=Nullable(Ref("FridaPhysicalStepReceiptV2")),
 callbackTranscriptRef=Nullable(Ref("TranscriptRefV2")),
 callbackSealReceiptSha256=Nullable(Ref("FridaPhysicalStepReceiptV2")),
 scriptUnloadReceiptSha256=Nullable(Ref("FridaPhysicalStepReceiptV2")),
 physicalDetachReceiptSha256=Nullable(Ref("FridaPhysicalStepReceiptV2")),
 operationLocalQuiescenceReceiptSha256=Nullable(Ref("FridaPhysicalStepReceiptV2")))
_row("FridaPhysicalSettlementBodyV2","E","CONTROL",**_FRIDA_PREFIX,serviceSessionId=ID,
     fridaLaneBodySha256=Ref("LaneBindingBodyV2"),initialSelectorSha256=Ref("PreAttachSelectorCommitV2"),
     observerSourceSha256=HASH,callbackCount=Integer(0,2),
     callbackRecordDigests=Vector(Ref("FridaCallbackRecordV2"),2),callbackChainRootSha256=HASH,
     physicalStepDispositions=Vector(Object("FridaStepDispositionV2"),7,7),
     physicalStepReceiptDigests=Vector(Nullable(Ref("FridaPhysicalStepReceiptV2")),7,7),
     physicalStepCursorStart=Const(0),physicalStepCursorEnd=Integer(0,7),
     callbackCursorStart=Const(0),callbackCursorEnd=Integer(0,2),physicalStepChainRootSha256=HASH,
     firstFailure=FAILURE,completedBeforeOperationDeadline=BOOL,
     physicalOutcome=Enum("detached-success","detached-failure","cleanup-uncertain"),
     rules=(Rule("mask",("physicalOutcome",),("detached-success",tuple(_FRIDA_PREFIX),("firstFailure",))),
       Rule("mask-in",("physicalOutcome",),(("detached-failure","cleanup-uncertain"),("firstFailure",),())),
       Rule("constant-if",("physicalOutcome","completedBeforeOperationDeadline"),("detached-success",True)),
       Rule("length",("callbackCount","callbackRecordDigests")),
       Rule("keyed-complete",("physicalStepDispositions",),(("ordinal","stepToken"),
          tuple((i,token) for i,token in enumerate(STEP_TOKENS)))),
       Rule("parallel-projection",("physicalStepDispositions","physicalStepReceiptDigests"),
          ("stepReceiptSha256",))))
_row("FridaBarrierRecordV2",globalRecordOrdinal=Integer(),previousServiceRecordSha256=HASH,
     beforePhaseRootSha256=Ref("SlotEvidenceEnvelopeV2"),
     fridaPhysicalSettlementEnvelopeSha256=Ref("FridaPhysicalSettlementEnvelopeV2"),
     physicalOutcome=Enum("detached-success","detached-failure","cleanup-uncertain"),
     acceptedMonotonicNs=HOST_TIME,terminal=Const(True))
_row("FridaCompositeReceiptV2",serviceSessionId=ID,fridaLaneBodySha256=Ref("LaneBindingBodyV2"),
     fridaPhysicalSettlementEnvelopeSha256=Nullable(Ref("FridaPhysicalSettlementEnvelopeV2")),
     fridaPhysicalOutcome=Enum("detached-success","detached-failure","cleanup-uncertain","never-started"),
     fridaLaneClosureRef=Object("LaneClosureRefV2"),firstFailure=FAILURE,
     completedBeforeOperationDeadline=BOOL,compositeClosureOutcome=Enum("closed-success","closed-failure","closed-uncertain"),
     rules=(Rule("mask",("fridaPhysicalOutcome",),("detached-success",("fridaPhysicalSettlementEnvelopeSha256",),("firstFailure",))),
       Rule("mask-in",("fridaPhysicalOutcome",),(("detached-failure","cleanup-uncertain"),("fridaPhysicalSettlementEnvelopeSha256","firstFailure"),())),
       Rule("mask",("fridaPhysicalOutcome",),("never-started",("firstFailure",),("fridaPhysicalSettlementEnvelopeSha256",))),
       Rule("constant-if",("fridaPhysicalOutcome","completedBeforeOperationDeadline"),("detached-success",True)),
       Rule("constant-if",("fridaPhysicalOutcome","completedBeforeOperationDeadline"),("cleanup-uncertain",False)),
       Rule("constant-if",("fridaPhysicalOutcome","completedBeforeOperationDeadline"),("never-started",False)),
       Rule("constant-if",("fridaPhysicalOutcome","compositeClosureOutcome"),("detached-success","closed-success")),
       Rule("constant-if",("fridaPhysicalOutcome","compositeClosureOutcome"),("detached-failure","closed-failure")),
       Rule("constant-if",("fridaPhysicalOutcome","compositeClosureOutcome"),("cleanup-uncertain","closed-uncertain")),
       Rule("constant-if",("fridaPhysicalOutcome","compositeClosureOutcome"),("never-started","closed-failure"))))

_row("LaneNeverStartedReceiptV2","E","CONTROL",laneBodySha256=Nullable(Ref("LaneBindingBodyV2")),
     lane=LANE,processCreated=BOOL,jobAssignmentReceiptSha256=Nullable(Ref("JobAssignmentReceiptV2")),
     resumed=Const(False),readyPublished=Const(False),
     epochAdmissionState=Enum("not-admitted","revoked","uncertain"),
     endpointCloseSetSha256=HASH,keyDestructionReceiptSha256=Nullable(Ref("KeyDestructionReceiptV2")),
     processJoinReceiptSha256=Nullable(Ref("JoinReceiptV2")),
     outcome=Enum("closed-failure","uncertain"),terminal=Const(True),
     rules=(Rule("mask",("processCreated",),(True,("jobAssignmentReceiptSha256","processJoinReceiptSha256"),())),
       Rule("mask",("processCreated",),(False,(),("jobAssignmentReceiptSha256","processJoinReceiptSha256")))))
_row("LaneClosureRefV2","E","CONTROL",lane=LANE,
     closureKind=Enum("proved-quiescent","terminal-unquiesced","never-started","missing-crashed"),
     capabilityTerminalEnvelopeSha256=Nullable(Ref("CapabilityTerminalEnvelopeV2")),
     capabilityQuiescenceEnvelopeSha256=Nullable(Ref("CapabilityQuiescenceEnvelopeV2")),
     neverStartedReceiptSha256=Nullable(Ref("LaneNeverStartedReceiptV2")),
     missingLayerReceiptSha256=Nullable(Ref("MissingLayerTerminalBodyV2")),
     acquisitionSnapshotRef=SNAPSHOT,outcome=Enum("closed-success","closed-failure","closed-uncertain"),
     rules=(Rule("mask",("closureKind",),("proved-quiescent",("capabilityTerminalEnvelopeSha256","capabilityQuiescenceEnvelopeSha256"),("neverStartedReceiptSha256","missingLayerReceiptSha256"))),
       Rule("mask",("closureKind",),("terminal-unquiesced",("capabilityTerminalEnvelopeSha256",),("capabilityQuiescenceEnvelopeSha256","neverStartedReceiptSha256","missingLayerReceiptSha256"))),
       Rule("mask",("closureKind",),("never-started",("neverStartedReceiptSha256",),("capabilityTerminalEnvelopeSha256","capabilityQuiescenceEnvelopeSha256","missingLayerReceiptSha256"))),
       Rule("mask",("closureKind",),("missing-crashed",("missingLayerReceiptSha256",),("capabilityQuiescenceEnvelopeSha256","neverStartedReceiptSha256")))))
_row("MissingLayerTerminalBodyV2","E","CONTROL",missingLayer=Enum("lane-authority","lane-frida",
     "guardian","service","supervisor","verifier"),
     missingProcessAcquisitionState=Object("AcquisitionStateV2"),
     emissionStatus=Enum("proved-missing","unobserved-uncertain"),observedOutputPrefixSha256=HASH,
     observedOutputByteLength=Integer(0,1048576),
     outputDisposition=Enum("empty-eof","invalid-prefix-eof","incomplete-prefix-timeout","not-created"),
     signingKeyAcquisitionState=Object("AcquisitionStateV2"),
     outputAcquisitionState=Object("AcquisitionStateV2"),processAcquisitionState=Object("AcquisitionStateV2"),
     observerLayer=Enum("service","supervisor","requester","outer"),observerIdentitySha256=PROCESS,
     observationReceiptSha256=Ref("PlatformObservationV2"),observedHostNs=HOST_TIME,
     cleanupDeadlineNs=HOST_TIME,firstFailure=Object("FirstFailureV2"),outcome=Const("emission-unavailable"),terminal=Const(True))
_row("MissingServiceTerminalReceiptV2",missingLayerReceiptSha256=Ref("MissingLayerTerminalBodyV2"),
     serviceIdentity=PROCESS,supervisorIdentity=PROCESS,outcome=Const("uncertain"))
_row("RemainingEmitterStateV2","E","CONTROL",emitterLayer=Enum("service","supervisor","verifier"),
     emitterIdentity=PROCESS,outputAcquisitionSha256=Ref("AcquisitionStateV2"),
     signingKeyAcquisitionSha256=Ref("AcquisitionStateV2"),processAcquisitionSha256=Ref("AcquisitionStateV2"),
     nextObserverIdentity=PROCESS)
_row("ConstructionSettlementBodyV2","P","LARGE",constructionId=ID,constructionCursor=Enum(*CONSTRUCTION_STEPS),
     executionState=Enum("not-built","built-unattested","attested-not-published"),
     candidateExecutionBodySha256=Nullable(Ref("ExecutionBindingBodyV2")),
     candidateExecutionAttestationSha256=Nullable(Ref("ExecutionAttestationEnvelopeV2")),
     acquisitionSnapshotRef=SNAPSHOT,firstFailure=Object("FirstFailureV2"),outerOwnerIdentity=PROCESS,
     outerCheckpointSha256=HASH,settlementDeadlineNs=HOST_TIME,observedNs=HOST_TIME,
     outcome=Enum("settled-abort","retained-uncertain"),
     rules=(Rule("mask",("executionState",),("not-built",(),("candidateExecutionBodySha256","candidateExecutionAttestationSha256"))),
       Rule("mask",("executionState",),("built-unattested",("candidateExecutionBodySha256",),("candidateExecutionAttestationSha256",))),
       Rule("mask",("executionState",),("attested-not-published",("candidateExecutionBodySha256","candidateExecutionAttestationSha256"),()))))
_row("PrePlanAbortBodyV2","N","LARGE",outerOwnerIdentity=PROCESS,outerImageSha256=HASH,
     constructionCursor=Enum(*CONSTRUCTION_STEPS),acquisitionSnapshotRef=SNAPSHOT,
     firstFailure=Object("FirstFailureV2"),settlementDeadlineNs=HOST_TIME,observedNs=HOST_TIME,
     prePlanCleanupExpiryEnvelopeSha256=Nullable(Ref("PrePlanCleanupExpiryEnvelopeV2")),
     outcome=Enum("settled-abort","retained-uncertain"))
_row("PrePlanCleanupExpiryReceiptV2","N","CONTROL",outerOwnerIdentitySha256=PROCESS,
     outerTrustAnchorSha256=Ref("TrustAnchorPinV2"),cleanupReservationSha256=Ref("AcquisitionReservationV2"),
     constructionCursor=Enum(*CONSTRUCTION_STEPS),settlementDeadlineNs=HOST_TIME,observedHostNs=HOST_TIME,
     completedConstructionPrefixSha256=HASH,acquisitionSnapshotRef=SNAPSHOT,
     firstFailure=Object("FirstFailureV2"),outcome=Const("pre-plan-cleanup-uncertain"))
_row("CleanupExpiryReceiptV2","X","CONTROL",cleanupDeadlineNs=HOST_TIME,
     observedMonotonicNs=HOST_TIME,operationName=Enum("lane-revoke","guardian-close","transcript-close",
       "service-close","supervisor-close","requester-close","construction-settle"),
     operationStarted=BOOL,acquisitionSnapshotRef=SNAPSHOT,nextRecoveryOwnerIdentity=PROCESS,
     outcome=Const("cleanup-deadline-uncertain"),
     rules=(Rule("mask",("outcome",),("cleanup-deadline-uncertain",("planCoreSha256",),())),))
_SNAPSHOT_COMMON=dict(serviceSessionId=ID,authorityLaneBodySha256=Ref("LaneBindingBodyV2"),
 brokerSlotCursorStart=Const(0),fridaCompositeClosureRecordSha256=Ref("ServiceGlobalRecordV2"),
 orderedTranscriptRefsSha256=Ref("TranscriptRefSetV2"),stabilityPolicySha256=Ref("StabilityPolicyV2"),
 authorityLaneClosureRef=Object("LaneClosureRefV2"),serviceRecordCursor=Integer())
_row("AuthoritySnapshotReceiptV2","E","CONTROL",**_SNAPSHOT_COMMON,brokerSlotCursorEnd=Const(24),
     slotRecordDigests=Vector(Ref("SlotEvidenceEnvelopeV2"),24,24),
     beforePhaseRootSha256=Ref("SlotEvidenceEnvelopeV2"),fridaBarrierRecordSha256=Ref("FridaBarrierRecordV2"),
     fridaPhysicalSettlementEnvelopeSha256=Ref("FridaPhysicalSettlementEnvelopeV2"),
     afterPhaseRootSha256=Ref("SlotEvidenceEnvelopeV2"),beforeEvidenceMapSha256=Ref("EvidenceMapV2"),
     afterEvidenceMapSha256=Ref("EvidenceMapV2"),stabilityResultSha256=Ref("StabilityResultV2"),
     outcome=Const("snapshot-success"))
_row("AuthoritySnapshotFailureReceiptV2","E","CONTROL",**_SNAPSHOT_COMMON,
     brokerSlotCursorAtFailure=Integer(0,24),completedSlotRecordDigests=Vector(Ref("SlotEvidenceEnvelopeV2"),24),
     firstFailureLayer=Enum(*LAYERS),firstFailureState=Enum(*STATES),
     firstFailureSlot=Nullable(Integer(0,23)),firstFailureOperation=AUTHORITY_FAILURE_OPERATION,
     firstFailureCode=Enum(*FAILURE_CODES),firstFailureEvidenceSha256=Nullable(HASH),
     beforePhaseRootSha256=Nullable(Ref("SlotEvidenceEnvelopeV2")),
     fridaBarrierRecordSha256=Nullable(Ref("FridaBarrierRecordV2")),
     fridaPhysicalSettlementEnvelopeSha256=Nullable(Ref("FridaPhysicalSettlementEnvelopeV2")),
     afterPhaseRootSha256=Nullable(Ref("SlotEvidenceEnvelopeV2")),
     partialEvidenceMapSha256=Ref("EvidenceMapV2"),stabilityResultSha256=Nullable(Ref("StabilityResultV2")),
     outcome=Enum("snapshot-failure","snapshot-uncertain"),
     rules=(Rule("length",("brokerSlotCursorAtFailure","completedSlotRecordDigests")),
            Rule("mask-in",("firstFailureOperation",),(("FRIDA_PHYSICAL_COMPOSITE","AUTHORITY_BARRIER","AUTHORITY_SNAPSHOT_CONTROL"),(),("firstFailureSlot",))),
            Rule("mask-in",("firstFailureOperation",),(AUTH_TOKENS,("firstFailureSlot",),()))))
_row("SuccessSealV2",serviceSessionId=ID,finalAcceptedEvidenceRootSha256=HASH,
     authoritySnapshotReceiptSha256=Ref("AuthoritySnapshotReceiptV2"),
     authorityLaneQuiescenceEnvelopeSha256=Ref("CapabilityQuiescenceEnvelopeV2"),
     fridaLaneQuiescenceEnvelopeSha256=Ref("CapabilityQuiescenceEnvelopeV2"),
     guardianClosureRootSha256=HASH,transcriptClosureRootSha256=HASH,
     fridaPhysicalSettlementEnvelopeSha256=Ref("FridaPhysicalSettlementEnvelopeV2"),
     sealedHostNs=HOST_TIME,operationDeadlineNs=HOST_TIME,state=Const("SUCCESS_SEALED"),
     rules=(Rule("less",("sealedHostNs","operationDeadlineNs")),))
_row("ServiceTerminalBodyV2","E","LARGE",serviceSessionId=ID,serviceProcessIdentity=PROCESS,
     outcome=Enum("success","failure","uncertain"),physicalSuccessCandidateSealedNs=Nullable(HOST_TIME),
     successSealSha256=Nullable(Ref("SuccessSealV2")),firstFailure=FAILURE,
     authoritySnapshotReceiptSha256=Nullable(Ref("AuthoritySnapshotReceiptV2")),
     authoritySnapshotFailureReceiptSha256=Nullable(Ref("AuthoritySnapshotFailureReceiptV2")),
     fridaPhysicalSettlementEnvelopeSha256=Nullable(Ref("FridaPhysicalSettlementEnvelopeV2")),
     fridaCompositeClosureRecordSha256=Ref("ServiceGlobalRecordV2"),
     authorityLaneClosureRef=Object("LaneClosureRefV2"),fridaLaneClosureRef=Object("LaneClosureRefV2"),
     guardianTerminalRootSha256=HASH,transcriptRootSha256=HASH,preTerminalServiceRecordRootSha256=HASH,
     preTerminalServiceRecordCursorFinal=Integer(),serviceOwnedCloseSetSha256=HASH,
     remainingOutputHandleIdentitySha256=OBJECT,remainingSigningHandleIdentitySha256=OBJECT,
     operationDeadlineNs=HOST_TIME,cleanupDeadlineNs=HOST_TIME,terminal=Const(True),
     rules=(Rule("mask",("outcome",),("success",("physicalSuccessCandidateSealedNs","successSealSha256","authoritySnapshotReceiptSha256","fridaPhysicalSettlementEnvelopeSha256"),("firstFailure","authoritySnapshotFailureReceiptSha256"))),
       Rule("mask",("outcome",),("failure",("firstFailure","authoritySnapshotFailureReceiptSha256"),("authoritySnapshotReceiptSha256",))),
       Rule("mask",("outcome",),("uncertain",("firstFailure","authoritySnapshotFailureReceiptSha256"),("authoritySnapshotReceiptSha256",))),
       Rule("not-equal",("remainingOutputHandleIdentitySha256","remainingSigningHandleIdentitySha256"))))
_row("ServiceObservationV2","E","CONTROL",kind=Enum("present","supervisor-attested-missing","unknown-because-supervisor-missing"),
     serviceTerminalEnvelopeSha256=Nullable(Ref("ServiceTerminalEnvelopeV2")),
     supervisorClosureEnvelopeSha256=Nullable(Ref("SupervisorClosureEnvelopeV2")),
     missingServiceObservationSha256=Nullable(Ref("MissingLayerTerminalBodyV2")),
     missingSupervisorObservationSha256=Nullable(Ref("MissingLayerTerminalBodyV2")),
     rules=(Rule("mask",("kind",),("present",("serviceTerminalEnvelopeSha256",),("supervisorClosureEnvelopeSha256","missingServiceObservationSha256","missingSupervisorObservationSha256"))),
       Rule("mask",("kind",),("supervisor-attested-missing",("supervisorClosureEnvelopeSha256","missingServiceObservationSha256"),("serviceTerminalEnvelopeSha256","missingSupervisorObservationSha256"))),
       Rule("mask",("kind",),("unknown-because-supervisor-missing",("missingSupervisorObservationSha256",),("serviceTerminalEnvelopeSha256","supervisorClosureEnvelopeSha256","missingServiceObservationSha256")))))
_row("SupervisorClosureBodyV2","E","LARGE",supervisorProcessIdentity=PROCESS,
     servicePredecessorKind=Enum("terminal-present","terminal-missing-proved","terminal-unobserved-uncertain"),
     serviceTerminalEnvelopeSha256=Nullable(Ref("ServiceTerminalEnvelopeV2")),
     missingServiceTerminalReceiptSha256=Nullable(Ref("MissingServiceTerminalReceiptV2")),
     serviceTerminalOutcome=Enum("success","failure","uncertain","missing"),
     serviceProvenanceVerificationReceiptSha256=Nullable(Ref("PlatformObservationV2")),
     serviceOutputEofReceiptSha256=Nullable(Ref("EndpointEofReceiptV2")),
     serviceSigningHandleCloseReceiptSha256=Nullable(Ref("CloseReceiptV2")),
     serviceProcessJoinReceiptSha256=Nullable(Ref("JoinReceiptV2")),
     serviceRemainingHandleCloseSetSha256=Nullable(HASH),jobIdentity=Ref("JobIdentityV2"),
     jobAssignmentRootSha256=HASH,jobActiveProcessCount=Integer(0,8),
     jobEmptyReceiptSha256=Nullable(Ref("JobEmptyReceiptV2")),
     guardianClosureRefs=Vector(Object("GuardianClosureRefV2"),5,5),
     allAcquisitionSnapshotRef=SNAPSHOT,supervisorOwnedCloseSetSha256=HASH,
     remainingSupervisorOutputHandleIdentitySha256=OBJECT,remainingSupervisorSigningHandleIdentitySha256=OBJECT,
     firstSupervisorFailure=FAILURE,closureOutcome=Enum("closed","uncertain"),
     cleanupDeadlineNs=HOST_TIME,terminal=Const(True),
     rules=(Rule("mask",("servicePredecessorKind",),("terminal-present",
        ("serviceTerminalEnvelopeSha256","serviceProvenanceVerificationReceiptSha256","serviceOutputEofReceiptSha256",
         "serviceSigningHandleCloseReceiptSha256","serviceProcessJoinReceiptSha256","serviceRemainingHandleCloseSetSha256"),
        ("missingServiceTerminalReceiptSha256",))),
       Rule("mask",("servicePredecessorKind",),("terminal-missing-proved",
        ("missingServiceTerminalReceiptSha256","serviceOutputEofReceiptSha256","serviceSigningHandleCloseReceiptSha256",
         "serviceProcessJoinReceiptSha256","serviceRemainingHandleCloseSetSha256"),
        ("serviceTerminalEnvelopeSha256","serviceProvenanceVerificationReceiptSha256",))),
       Rule("mask",("servicePredecessorKind",),("terminal-unobserved-uncertain",
        ("missingServiceTerminalReceiptSha256",),("serviceTerminalEnvelopeSha256","serviceProvenanceVerificationReceiptSha256"))),
       Rule("not-constant-if",("servicePredecessorKind","serviceTerminalOutcome"),("terminal-present","missing")),
       Rule("constant-if",("servicePredecessorKind","serviceTerminalOutcome"),("terminal-missing-proved","missing")),
       Rule("constant-if",("servicePredecessorKind","serviceTerminalOutcome"),("terminal-unobserved-uncertain","missing")),
       Rule("envelope-body-field-equal",("serviceTerminalEnvelopeSha256","serviceTerminalOutcome"),
          ("ServiceTerminalEnvelopeV2","ServiceTerminalBodyV2","outcome")),
       Rule("constant-if",("servicePredecessorKind","closureOutcome"),("terminal-unobserved-uncertain","uncertain")),
       Rule("mask",("closureOutcome",),("closed",("jobEmptyReceiptSha256",),("firstSupervisorFailure",))),
       Rule("mask",("closureOutcome",),("uncertain",("firstSupervisorFailure",),())),
       Rule("constant-if",("closureOutcome","jobActiveProcessCount"),("closed",0)),
       Rule("keyed-complete",("guardianClosureRefs",),(("fileRole",),tuple((x,) for x in FILE_ROLE.args))),
       Rule("not-equal",("remainingSupervisorOutputHandleIdentitySha256","remainingSupervisorSigningHandleIdentitySha256"))))
_row("RequesterBridgeBodyV2","E","CONTROL",serviceTerminalEnvelopeSha256=Ref("ServiceTerminalEnvelopeV2"),
     supervisorClosureEnvelopeSha256=Ref("SupervisorClosureEnvelopeV2"),
     supervisorOutputEofReceiptSha256=Ref("EndpointEofReceiptV2"),
     supervisorSigningHandleCloseReceiptSha256=Ref("CloseReceiptV2"),supervisorProcessJoinReceiptSha256=Ref("JoinReceiptV2"),
     authoritySnapshotReceiptSha256=Ref("AuthoritySnapshotReceiptV2"),
     fridaPhysicalSettlementEnvelopeSha256=Ref("FridaPhysicalSettlementEnvelopeV2"),
     fridaCompositeClosureRecordSha256=Ref("ServiceGlobalRecordV2"),
     compatibilityProjectionSha256=Ref("NativePageCompatibilityProjectionV2"),
     logicalReceiptTemplateRootSha256=HASH,bridgeNonce=ID,constructedMonotonicNs=HOST_TIME,
     constructionCursor=Const(0),constructedAfterCompleteClosure=Const(True))
_RQ_FIELDS=dict(bridgeBodySha256=Nullable(Ref("RequesterBridgeBodyV2")),
 bridgeValidationReceiptSha256=Nullable(Ref("PlatformObservationV2")),
 logicalReceiptChainRootSha256=Nullable(HASH),
 authorityFacadeTerminalReceiptSha256=Nullable(Ref("LogicalMethodReceiptBodyV2")),
 fridaFacadeTerminalReceiptSha256=Nullable(Ref("LogicalMethodReceiptBodyV2")),
 callbackDeliveryRootSha256=Nullable(HASH),localQuiescenceReceiptSha256=Nullable(Ref("OwnerQuiescenceReceiptV2")))
_row("RequesterTerminalBodyV2","E","LARGE",**_RQ_FIELDS,serviceObservation=Object("ServiceObservationV2"),
     supervisorPredecessorKind=Enum("closure-present","closure-missing-proved","closure-unobserved-uncertain"),
     supervisorClosureEnvelopeSha256=Nullable(Ref("SupervisorClosureEnvelopeV2")),
     missingSupervisorClosureReceiptSha256=Nullable(Ref("MissingLayerTerminalBodyV2")),
     supervisorClosureObservationReceiptSha256=Nullable(Ref("PlatformObservationV2")),
     globalConsumptionCursorFinal=Integer(0,64),firstRequesterFailure=FAILURE,
     requesterOutcome=Enum("success","failure","uncertain"),terminal=Const(True),
     rules=(Rule("mask",("requesterOutcome",),("success",tuple(_RQ_FIELDS),("firstRequesterFailure",))),
       Rule("mask",("requesterOutcome",),("failure",("firstRequesterFailure",),())),
       Rule("mask",("requesterOutcome",),("uncertain",("firstRequesterFailure",),())),
       Rule("constant-if",("requesterOutcome","supervisorPredecessorKind"),("success","closure-present")),
       Rule("mask",("supervisorPredecessorKind",),("closure-present",
          ("supervisorClosureEnvelopeSha256","supervisorClosureObservationReceiptSha256"),
          ("missingSupervisorClosureReceiptSha256",))),
       Rule("mask",("supervisorPredecessorKind",),("closure-missing-proved",
          ("missingSupervisorClosureReceiptSha256","supervisorClosureObservationReceiptSha256"),
          ("supervisorClosureEnvelopeSha256",))),
       Rule("mask",("supervisorPredecessorKind",),("closure-unobserved-uncertain",
          ("missingSupervisorClosureReceiptSha256",),
          ("supervisorClosureEnvelopeSha256","supervisorClosureObservationReceiptSha256",))),
       Rule("constant-if",("supervisorPredecessorKind","requesterOutcome"),("closure-unobserved-uncertain","uncertain"))))
_row("VerifierCrashRequesterBodyV2","E","LARGE",serviceObservation=Object("ServiceObservationV2"),
     missingVerifierReceiptSha256=Ref("MissingLayerTerminalBodyV2"),
     verifierAcquisitionState=Object("AcquisitionStateV2"),registryGeneration=ID,
     lastLogicalReceiptSha256=Nullable(Ref("LogicalMethodReceiptBodyV2")),
     outerOwnerIdentity=PROCESS,cleanupDeadlineNs=HOST_TIME,reservedSlotId=ID,
     callbackWorkerAcquisitionState=Object("AcquisitionStateV2"),firstFailure=Object("FirstFailureV2"),
     requesterOutcome=Const("uncertain"),terminal=Const(True))
_row("RequesterTerminalRegistryV2","E","CONTROL",outerOwnerIdentity=PROCESS,
     verifierAcquisitionState=Object("AcquisitionStateV2"),reservedSlotId=ID,
     winnerKind=Enum("verifier-terminal","outer-verifier-crash","publication-uncertain"),
     winnerBodySchema=Enum("RequesterTerminalBodyV2","VerifierCrashRequesterBodyV2","PublicationUncertainReceiptV2"),
     winnerBodySha256=Ref("RequesterTerminalBodyV2","VerifierCrashRequesterBodyV2","PublicationUncertainReceiptV2"),
     commitReceiptSha256=Nullable(Ref("PlatformObservationV2")),
     rules=(Rule("mask",("winnerKind",),("publication-uncertain",(),("commitReceiptSha256",))),
       Rule("mask",("winnerKind",),("verifier-terminal",("commitReceiptSha256",),())),
       Rule("mask",("winnerKind",),("outer-verifier-crash",("commitReceiptSha256",),())),
       Rule("dispatch-schema-ref",("winnerKind","winnerBodySchema","winnerBodySha256"),(
          ("verifier-terminal",("RequesterTerminalBodyV2",)),
          ("outer-verifier-crash",("VerifierCrashRequesterBodyV2",)),
          ("publication-uncertain",("PublicationUncertainReceiptV2",))))))

_row("AdmissionProjectionV2",provider=Enum("authority","frida"),imageManifestSha256=Ref("WorkerImagePinV2"),
     factoryPolicySha256=HASH,laneTerminalEnvelopeSha256=Ref("CapabilityTerminalEnvelopeV2"),
     laneQuiescenceEnvelopeSha256=Ref("CapabilityQuiescenceEnvelopeV2"),admitted=Const(True))
_row("StageProjectionV2","E","CONTROL",phase=PHASE,slotFirst=Integer(0,12),slotLast=Integer(11,23),
     slotRecordDigests=Vector(Ref("SlotEvidenceEnvelopeV2"),12,12),phaseRootSha256=Ref("SlotEvidenceEnvelopeV2"),
     evidenceMapSha256=Ref("EvidenceMapV2"),taskAuthoritySha256=Ref("ParsedAuthorityV2"),
     placementAttestationSha256=Ref("SupervisorDetachedAttestationEnvelopeV2"),
     penAttestationSha256=Ref("SupervisorDetachedAttestationEnvelopeV2"),
     checkpointAttestationSha256=Ref("SupervisorDetachedAttestationEnvelopeV2"),
     transcriptRefs=Vector(Object("TranscriptRefV2"),16),stabilityProjectionSha256=Ref("StabilityResultV2"))
_row("FridaLogicalProjectionV2",logicalAttachBindingSha256=Ref("LogicalAttachBindingV2"),
     physicalSettlementEnvelopeSha256=Ref("FridaPhysicalSettlementEnvelopeV2"),
     compositeClosureRecordSha256=Ref("ServiceGlobalRecordV2"),callbackTranscriptRef=Ref("TranscriptRefV2"),
     callbackCount=Const(2),callbackChainRootSha256=HASH,
     sealReceiptSha256=Ref("FridaPhysicalStepReceiptV2"),unloadReceiptSha256=Ref("FridaPhysicalStepReceiptV2"),
     detachReceiptSha256=Ref("FridaPhysicalStepReceiptV2"),physicalOutcome=Const("detached-success"))
_row("PhysicalClosureProjectionV2","E","CONTROL",
     authorityLaneTerminalEnvelopeSha256=Ref("CapabilityTerminalEnvelopeV2"),
     authorityLaneQuiescenceEnvelopeSha256=Ref("CapabilityQuiescenceEnvelopeV2"),
     fridaLaneTerminalEnvelopeSha256=Ref("CapabilityTerminalEnvelopeV2"),
     fridaLaneQuiescenceEnvelopeSha256=Ref("CapabilityQuiescenceEnvelopeV2"),
     guardianTerminalRootSha256=HASH,transcriptHopClosureRootSha256=HASH,
     serviceTerminalEnvelopeSha256=Ref("ServiceTerminalEnvelopeV2"),
     serviceSigningHandleCloseReceiptSha256=Ref("CloseReceiptV2"),serviceOutputEofReceiptSha256=Ref("EndpointEofReceiptV2"),
     serviceProcessJoinReceiptSha256=Ref("JoinReceiptV2"),supervisorClosureEnvelopeSha256=Ref("SupervisorClosureEnvelopeV2"),
     supervisorSigningHandleCloseReceiptSha256=Ref("CloseReceiptV2"),supervisorOutputEofReceiptSha256=Ref("EndpointEofReceiptV2"),
     supervisorProcessJoinReceiptSha256=Ref("JoinReceiptV2"),jobEmptyReceiptSha256=Ref("JobEmptyReceiptV2"))
_row("NativePageCompatibilityProjectionV2","E","PROJECTION",
     serviceTerminalEnvelopeSha256=Ref("ServiceTerminalEnvelopeV2"),
     supervisorClosureEnvelopeSha256=Ref("SupervisorClosureEnvelopeV2"),
     authorityAdmissionProjection=Object("AdmissionProjectionV2"),fridaAdmissionProjection=Object("AdmissionProjectionV2"),
     authoritySnapshotReceiptSha256=Ref("AuthoritySnapshotReceiptV2"),
     fridaPhysicalSettlementEnvelopeSha256=Ref("FridaPhysicalSettlementEnvelopeV2"),
     fridaCompositeClosureRecordSha256=Ref("ServiceGlobalRecordV2"),
     beforeStageProjection=Object("StageProjectionV2"),afterStageProjection=Object("StageProjectionV2"),
     fridaLogicalProjection=Object("FridaLogicalProjectionV2"),
     orderedTranscriptRefs=Vector(Object("TranscriptRefV2"),16),
     stabilityResultSha256=Ref("StabilityResultV2"),physicalClosureProjection=Object("PhysicalClosureProjectionV2"),
     failureProjection=Const(None))
_row("NativePageCompatibilityFailureProjectionV2","E","PROJECTION",
     serviceTerminalEnvelopeSha256=Ref("ServiceTerminalEnvelopeV2"),
     supervisorClosureEnvelopeSha256=Ref("SupervisorClosureEnvelopeV2"),
     authoritySnapshotFailureReceiptSha256=Ref("AuthoritySnapshotFailureReceiptV2"),
     fridaPhysicalSettlementEnvelopeSha256=Nullable(Ref("FridaPhysicalSettlementEnvelopeV2")),
     fridaCompositeClosureRecordSha256=Ref("ServiceGlobalRecordV2"),firstFailure=Object("FirstFailureV2"),
     completedTranscriptRefs=Vector(Object("TranscriptRefV2"),16),
     physicalClosureProjection=Nullable(Object("PhysicalClosureProjectionV2")),
     localFailureMapping=Object("LocalFailureMappingV2"))
_row("CompatibilityProjectionDescriptorV2",projectionKind=Enum("success","failure"),
     projectionSchema=Enum("NativePageCompatibilityProjectionV2","NativePageCompatibilityFailureProjectionV2"),
     canonicalEncoding=Const("utf8-canonical-json-v2"),projectionByteLength=Integer(1,131072),
     projectionSha256=Ref("NativePageCompatibilityProjectionV2","NativePageCompatibilityFailureProjectionV2"))
_PUBLIC_ERRORS=("GraphRunnerError","HardwareAdmissionBlocked","DeadlineExceeded","SnapshotRejected",
 "ProviderQuiescenceFailure","AuthorityProviderQuiescenceFailure","FridaProviderQuiescenceFailure","AuthorityReceiptFailure")
_row("LocalFailureMappingV2",sourceLayer=Enum(*LAYERS),sourceState=Enum(*STATES),
     sourceCode=Enum(*FAILURE_CODES),sourceReceiptSha256=Ref("FirstFailureV2"),facadeKind=Enum(*FACADES),
     logicalMethod=Enum(*METHODS),publicFailureCode=Enum(*_PUBLIC_ERRORS),retryable=Const(False))
_row("LogicalFailureBodyV2",layer=Enum(*LAYERS),method=Enum(*METHODS),code=Enum(*FAILURE_CODES),
     callbackIndex=Nullable(Integer(0,1)),completedCallbackCount=Integer(0,2),
     sourceReceiptSha256=Ref("FirstFailureV2"),causeDigestSha256=HASH,firstFailure=Const(True))
_row("LogicalFailurePolicyV2",policyId=Const("receipt-only-no-retry-v2"),
     callbackDeliveryDeadlineNs=HOST_TIME,allowedMethods=Tuple(*(Const(x) for x in METHODS)),
     failureCodeRegistrySha256=HASH,failClosed=Const(True))
_row("LogicalReceiptTemplateV2",compatibilityProjectionSha256=Ref("NativePageCompatibilityProjectionV2"),
     serviceTerminalEnvelopeSha256=Ref("ServiceTerminalEnvelopeV2"),
     supervisorClosureEnvelopeSha256=Ref("SupervisorClosureEnvelopeV2"),
     templateIndex=Integer(0,63),globalConsumptionOrdinal=Integer(0,63),
     facadeKind=Enum(*FACADES),method=Enum(*METHODS),requiredFacadeCursorBefore=Integer(0,63),
     requiredStateBefore=Enum(*STATES),successFacadeCursorAfter=Integer(1,64),
     successStateAfter=Enum(*STATES),successPhysicalBindingKind=Enum("authority-admission","frida-admission",
        "stage-before","stage-after","logical-attach","frida-settlement","callback-seal","script-unload",
        "session-detach","physical-closure","local-closure"),successPhysicalBindingSha256=HASH,
     successProjectionSha256=HASH,callbackPolicy=Enum("none","isolated-two-records"),
     failurePolicySha256=Ref("LogicalFailurePolicyV2"),terminalForFacadeOnSuccess=BOOL)
_row("LogicalMethodReceiptBodyV2","E","CONTROL",bridgeBodySha256=Ref("RequesterBridgeBodyV2"),
     templateBodySha256=Ref("LogicalReceiptTemplateV2"),facadeId=ID,facadeKind=Enum(*FACADES),
     method=Enum(*METHODS),globalConsumptionOrdinal=Integer(0,63),
     facadeCursorBefore=Integer(0,63),facadeCursorAfter=Integer(1,64),
     stateBefore=Enum(*STATES),stateAfter=Enum(*STATES),previousLogicalReceiptSha256=HASH,
     outcome=Enum("success","failure"),physicalReceiptSha256=Nullable(HASH),projectionSha256=Nullable(HASH),
     callbackRange=Nullable(Tuple(Integer(0,2),Integer(0,2))),
     callbackChainRootSha256=Nullable(HASH),deliveredCallbackCount=Integer(0,2),
     failure=Nullable(Object("LogicalFailureBodyV2")),
     localQuiescenceSha256=Nullable(Ref("OwnerQuiescenceReceiptV2")),terminalForFacade=BOOL,
     rules=(Rule("advance-one",("facadeCursorBefore","facadeCursorAfter")),
       Rule("mask",("outcome",),("success",(),("failure",))),
       Rule("mask",("outcome",),("failure",("failure",),()))))
_row("CallbackDeliveryAckV2",bridgeSha256=Ref("RequesterBridgeBodyV2"),logicalOperationId=ID,
     callbackIndex=Integer(0,1),callbackRecordSha256=Ref("FridaCallbackRecordV2"),
     publicationGeneration=ID,isolatedReceiverIdentity=PROCESS,
     result=Enum("returned","raised","disconnected","timed-out","reentrancy"),acceptedMonotonicNs=HOST_TIME)
_SUBJECTS=("PlacementSubjectV2","PenLeaseSubjectV2","CheckpointSubjectV2","ToolBundleSubjectV2",
 "PrivateAdbSubjectV2","SelectorSubjectV2","GuardianProcessSubjectV2","GuardianLeaseGrantV2",
 "WorkGateBodyV2","BootstrapResumeReceiptV2","ProcessResumeReceiptV2","InitialFileObservationV2",
 "LiveTargetBindingV2","LiveHostBindingV2","PreAttachSelectorCommitV2","GuardianProcessClosureReceiptV2",
 "PlatformObservationV2")
_row("SupervisorDetachedAttestationBodyV2","E","CONTROL",serviceSessionId=ID,
     attestationKind=Enum(*_SUBJECTS),subjectSchema=Enum(*_SUBJECTS),challenge=ID,captureId=ID,
     capturedMonotonicNs=HOST_TIME,providerIdentitySha256=PROCESS,
     subjectBodySha256=Ref(*_SUBJECTS),
     previousAttestationSha256=Nullable(Ref("SupervisorDetachedAttestationEnvelopeV2")),
     operationDeadlineNs=HOST_TIME,rules=(Rule("equal",("attestationKind","subjectSchema")),
       Rule("dispatch-schema-ref",("attestationKind","subjectSchema","subjectBodySha256"),
          tuple((x,(x,)) for x in _SUBJECTS))))
_PLATFORM_SUBJECTS=("ProcessIdentityV2","WindowsObjectIdentityV2","GuardianFdIncarnationV2",
 "AcquisitionReservationV2","AcquisitionResultV2","GuardianSyscallReceiptV2",
 "CapabilityOperationReceiptV2","AuthorityBarrierAcceptanceV2","ParsedAuthorityV2",
 "TranscriptRefV2","ServiceTerminalEnvelopeV2","SupervisorClosureEnvelopeV2","RequesterBridgeBodyV2",
 "RequesterTerminalBodyV2","VerifierCrashRequesterBodyV2","PublicationUncertainReceiptV2",
 "TargetProcessEvidenceV2","DeviceStateEvidenceV2","FileStatV2","JobMemberSetV2",
 "AcquisitionSnapshotBodyV2")
_row("PlatformObservationV2","X",operation=Enum("capture","parse","provider-proof","acceptance",
 "causal-launch","causal-attach","durability","canonical-validation","transport-close",
 "bridge-validation","closure-observation","terminal-commit","immutable-owner-boundary",
 "fd-syscall","staging-delete","exit-intent"),
     ownerIdentity=PROCESS,subjectSchema=Enum(*_PLATFORM_SUBJECTS),
     subjectSha256=Ref(*_PLATFORM_SUBJECTS),operationId=ID,observationOrdinal=Integer(),
     previousObservationSha256=Nullable(Ref("PlatformObservationV2")),sourceImageSha256=HASH,
     sourcePolicySha256=HASH,capturedHostNs=HOST_TIME,operationDeadlineNs=HOST_TIME,outcome=OUTCOME,
     rules=(Rule("dispatch-ref",("subjectSchema","subjectSha256"),
                 tuple((x,(x,)) for x in _PLATFORM_SUBJECTS)),))
_SLOT_EVIDENCE=("PhaseOpenEvidenceV2","DeviceStateEvidenceV2","TargetProcessEvidenceV2",
 "GuardianFileDigestEvidenceV2","GuardianAbsenceBeforeEvidenceV2","GuardianAbsenceAfterEvidenceV2",
 "ParsedTranscriptEvidenceV2","PhaseSealEvidenceV2")
_row("SlotEvidenceBodyV2","E","CONTROL",authorityLaneBodySha256=Ref("LaneBindingBodyV2"),
     serviceSessionId=ID,brokerSlot=Integer(0,23),phase=PHASE,laneOperationCursor=Integer(0,23),
     globalRecordOrdinal=Integer(),operationToken=Enum(*AUTH_TOKENS),captureId=ID,
     capturedMonotonicNs=HOST_TIME,typedEvidenceSchema=Enum(*_SLOT_EVIDENCE),
     typedEvidence=Choice(*_SLOT_EVIDENCE),typedEvidenceSha256=Ref(*_SLOT_EVIDENCE),
     transcriptRefs=Vector(Object("TranscriptRefV2"),16),previousSlotRecordSha256=HASH,
     operationDeadlineNs=HOST_TIME,rules=(Rule("field-schema",("typedEvidenceSchema","typedEvidence")),))

def _signed(name,phase,bodies,key,profile,attestation_field,attestation_target,
            key_field="signingKeyId",**extra):
    bodies=tuple(sorted(bodies))
    _fields=dict(bodySchema=Enum(*bodies),bodyByteLength=Integer(1,1048576),
        bodySha256=Ref(*bodies),signatureAlgorithm=Const("Ed25519"),signature=Base64(64),**extra)
    _fields[key_field]=ID
    _fields[attestation_field]=Ref(attestation_target)
    _row(name,phase,bodies=tuple(bodies),key=key,profile=profile,
         purposes=("envelope-hash","signature"),**_fields)

_signed("SupervisorKeyAttestationEnvelopeV2","P",("SupervisorKeyAttestationBodyV2",),
 "supervisor-root","ed25519-P","supervisorTrustAnchorSha256","TrustAnchorPinV2")
_signed("PBoundObservationEnvelopeV2","P",("ServiceBootstrapResumeReceiptV2",
 "ServiceBootstrapEffectReceiptV2","ServiceKeyBootstrapReceiptV2","JobAssignmentReceiptV2",
 "AckControlFactoryBindingV2","HopFactoryBindingV2"),
 "supervisor-P","ed25519-P","supervisorKeyAttestationSha256","SupervisorKeyAttestationEnvelopeV2")
_signed("ExecutionAttestationEnvelopeV2","E",("ExecutionBindingBodyV2",),
 "supervisor-P","ed25519-E","supervisorKeyAttestationSha256","SupervisorKeyAttestationEnvelopeV2")
for _envelope,_body in (
 ("ChildStreamKeyAttestationEnvelopeV2","ChildStreamKeyAttestationBodyV2"),
 ("GuardianStreamKeyAttestationEnvelopeV2","GuardianStreamKeyAttestationBodyV2"),
 ("LogicalAttachBindingEnvelopeV2","LogicalAttachBindingV2"),
 ("SupervisorClosureEnvelopeV2","SupervisorClosureBodyV2")):
    _signed(_envelope,"E",(_body,),"supervisor-E","ed25519-E",
            "supervisorKeyAttestationSha256","SupervisorKeyAttestationEnvelopeV2")
_signed("SupervisorDetachedAttestationEnvelopeV2","E",("SupervisorDetachedAttestationBodyV2",),
 "supervisor-E","ed25519-E","supervisorKeyAttestationSha256","SupervisorKeyAttestationEnvelopeV2",
 key_field="supervisorSigningKeyId")
_signed("ServiceTerminalEnvelopeV2","E",("ServiceTerminalBodyV2",),
 "service-E","ed25519-E","executionAttestationSha256","ExecutionAttestationEnvelopeV2")
_signed("ConstructionSettlementEnvelopeV2","P",("ConstructionSettlementBodyV2",),
 "outer-root","ed25519-P","outerTrustAnchorSha256","TrustAnchorPinV2")
for _envelope,_body in (("PrePlanAbortEnvelopeV2","PrePlanAbortBodyV2"),
                       ("PrePlanCleanupExpiryEnvelopeV2","PrePlanCleanupExpiryReceiptV2")):
    _signed(_envelope,"N",(_body,),"outer-root","ed25519-N","outerTrustAnchorSha256","TrustAnchorPinV2")

def _mac_envelope(name,bodies,key,profile="hmac-E",**extra):
    bodies=tuple(sorted(bodies))
    _row(name,bodies=tuple(bodies),key=key,profile=profile,purposes=("envelope-hash","mac"),
         bodySchema=Enum(*bodies),bodyByteLength=Integer(1,65536),bodySha256=Ref(*bodies),
         algorithm=Const("HMAC-SHA256"),keyId=ID,tag=Base64(32),**extra)

for _envelope,_body in (("CapabilityTerminalEnvelopeV2","CapabilityTerminalBodyV2"),
 ("CapabilityQuiescenceEnvelopeV2","CapabilityQuiescenceBodyV2"),
 ("FridaPhysicalSettlementEnvelopeV2","FridaPhysicalSettlementBodyV2"),
 ("SlotEvidenceEnvelopeV2","SlotEvidenceBodyV2")):
    _mac_envelope(_envelope,(_body,),"lane",laneBodySha256=Ref("LaneBindingBodyV2"))
for _envelope,_body in (("InlineTerminalEnvelopeV2","InlineTerminalBodyV2"),
                       ("BulkManifestEnvelopeV2","BulkManifestBodyV2")):
    _mac_envelope(_envelope,(_body,),"transfer-terminal",authorIdentity=PROCESS,
        dataEndpointBindingSha256=Ref("DataEndpointBindingV2"),
        keyAttestationSha256=Ref("HopFactoryBindingV2"))
_mac_envelope("SettlementAckEnvelopeV2",("SettlementAckV2",),"transfer-ack","hmac-settlement",
     dataEndpointBindingSha256=Ref("DataEndpointBindingV2"),
     ackControlBindingSha256=Ref("AckControlBindingV2"),receiverIdentitySha256=PROCESS,ackOrdinal=Const(0))
_mac_envelope("GuardianHopTerminalEnvelopeV2",("GuardianHopTerminalBodyV2",),"guardian-terminal",
     "hmac-guardian-hop",hopBindingSha256=Ref("GuardianHopBindingV2"))
_mac_envelope("GuardianControlEnvelopeV2",("GuardianControlBodyV2",),"guardian-control",
     "hmac-guardian-control",guardianSessionId=ID,streamReservationSha256=Ref("GuardianStreamReservationV2"),
     hopBindingSha256=Nullable(Ref("GuardianHopBindingV2")),controlSequence=Integer(),
     direction=Enum("sender-control","receiver-control"),controlClass=Enum("bootstrap","normal","terminalization"))
_ACK_CONTROL_DISPATCH=(
    ("offer",("EndpointOfferV2",)),
    ("accept",("EndpointAcceptV2",)),
    ("grant",("EndpointFirstWriteGrantV2",)),
    ("settlement",("SettlementAckEnvelopeV2",)),
    ("carrier-terminal",("InlineTerminalEnvelopeV2","BulkManifestEnvelopeV2")),
    ("close",("AckControlCloseBodyV2",)),
)
_mac_envelope("AckControlEnvelopeV2",("EndpointOfferV2","EndpointAcceptV2","EndpointFirstWriteGrantV2",
     "SettlementAckEnvelopeV2","InlineTerminalEnvelopeV2","BulkManifestEnvelopeV2","AckControlCloseBodyV2"),
     "ack-control","hmac-ack-control",ackControlBindingSha256=Ref("AckControlBindingV2"),
     direction=Enum("sender-control","receiver-control"),sequenceClass=Enum("normal","terminalization"),
     messageSequence=Integer(),previousEnvelopeSha256=HASH,
     kind=Enum("offer","accept","grant","settlement","carrier-terminal","close"),
     rules=(Rule("dispatch-schema-ref",("kind","bodySchema","bodySha256"),_ACK_CONTROL_DISPATCH),))

_row("BootstrapHandleEntryV2","X",ownerIdentity=PROCESS,objectIdentity=OBJECT,
     objectKind=Enum("process","thread","job","pipe-read","pipe-write","key","store","spool","gate","drain"),
     nativeValue=U64,generation=ID,grantedRights=Vector(Enum("read","write","synchronize","query",
     "duplicate","terminate","assign","read-control"),8,1),noninheritable=Const(True),
     acquisitionReceiptSha256=Ref("AcquisitionResultV2"),closeOwnerIdentity=PROCESS)
_row("BootstrapHandleSetBodyV2","X","LARGE",ownerIdentity=PROCESS,entryCount=Integer(0,512),
     entries=Vector(Object("BootstrapHandleEntryV2"),512),observationOrdinal=Integer(),
     completeEnumerationReceiptSha256=Ref("PlatformObservationV2"),
     rules=(Rule("length",("entryCount","entries")),Rule("unique",("entries",))))
_row("ZeroAuthorityHandleSetBodyV2","X","SMALL",ownerIdentity=PROCESS,
     completeHandleSetSha256=Ref("BootstrapHandleSetBodyV2"),
     observedObjectKinds=Tuple(*(Const(x) for x in ("process","thread","job","pipe-read",
         "pipe-write","key","store","spool","gate","drain"))),
     authorityBearingEntries=Vector(Ref("BootstrapHandleEntryV2"),0),authorityCount=Const(0),
     observationReceiptSha256=Ref("PlatformObservationV2"))
_row("PreGateRetainedHandleRootBodyV2","E","CONTROL",
     retainedHandleSetSha256=Ref("BootstrapHandleSetBodyV2"),
     authorityLaneBindingSha256=Ref("LaneBindingBodyV2"),fridaLaneBindingSha256=Ref("LaneBindingBodyV2"),
     serviceIdentity=PROCESS,supervisorIdentity=PROCESS,
     originalOperationDeadlineNs=HOST_TIME,complete=Const(True))
_row("OuterControlBindingBodyV2","X",senderIdentity=PROCESS,receiverIdentity=PROCESS,
     sendObjectIdentity=OBJECT,receiveObjectIdentity=OBJECT,generation=ID,direction=Const("send-only"),
     inherited=Const(False),keyId=ID,acquisitionReceiptSha256=Ref("AcquisitionResultV2"),
     closeOwnerIdentity=PROCESS,originalDeadlineNs=HOST_TIME)
_row("SnapshotTransportBindingV2","X","CONTROL",namespace=Const("construction-snapshot-v2"),
     senderIdentity=PROCESS,receiverIdentity=PROCESS,outerOwnerIdentity=PROCESS,
     sendEndpointIdentity=OBJECT,receiveEndpointIdentity=OBJECT,
     ackControlBindingSha256=Ref("OuterControlBindingBodyV2"),
     generation=ID,masterKeyId=ID,keyDeliveryReceiptSha256=Ref("AcquisitionResultV2"),
     acquisitionReceiptSha256=Ref("AcquisitionResultV2"),originalDeadlineNs=HOST_TIME,
     maxSnapshotBytes=Const(2101761),maxChunks=Const(33),maxChunkBytes=Const(65536),
     purposes=("body-hash","hkdf-salt","hkdf-info","key-id"))
_row("SnapshotTransportChunkV2","X",bindingSha256=Ref("SnapshotTransportBindingV2"),
     directionKeyId=ID,chunkOrdinal=Integer(0,32),offset=Integer(0,2101760),
     chunkByteLength=Integer(1,65536),chunkSha256=HASH,previousRecordSha256=HASH,
     originalDeadlineNs=HOST_TIME,purposes=("body-hash","genesis","record-hash","frame-mac"))
_row("SnapshotTransportSettlementV2","X","CONTROL",bindingSha256=Ref("SnapshotTransportBindingV2"),
     snapshotSha256=Ref("AcquisitionSnapshotBodyV2"),snapshotByteLength=Integer(1,2101761),
     chunkCount=Integer(1,33),finalChunkRecordSha256=HASH,
     receiverEofReceiptSha256=Ref("EndpointEofReceiptV2"),
     receiverValidationReceiptSha256=Ref("PlatformObservationV2"),
     receiverCloseReceiptSha256=Ref("EndpointCloseReceiptV2"),
     receiverPayloadKeyDestructionReceiptSha256=Ref("KeyDestructionReceiptV2"),
     ackOrdinal=Const(0))
_row("SnapshotTransportTerminalV2","X","CONTROL",bindingSha256=Ref("SnapshotTransportBindingV2"),
     snapshotSha256=Ref("AcquisitionSnapshotBodyV2"),snapshotByteLength=Integer(1,2101761),
     settlementEnvelopeSha256=Nullable(Ref("SnapshotTransportControlEnvelopeV2")),
     senderPayloadKeyDestructionReceiptSha256=Nullable(Ref("KeyDestructionReceiptV2")),
     senderCloseReceiptSha256=Nullable(Ref("EndpointCloseReceiptV2")),
     firstFailure=FAILURE,outcome=Enum("closed","uncertain"),terminal=Const(True),
     rules=(Rule("mask",("outcome",),("closed",("settlementEnvelopeSha256",
        "senderPayloadKeyDestructionReceiptSha256","senderCloseReceiptSha256"),("firstFailure",))),
       Rule("mask",("outcome",),("uncertain",("firstFailure",),()))))
_signed("SnapshotTransportAttestationEnvelopeV2","X",("SnapshotTransportBindingV2",),
     "outer-root","ed25519-X","outerTrustAnchorSha256","TrustAnchorPinV2")
_signed("PlatformObservationEnvelopeV2","X",("PlatformObservationV2",),
     "outer-root","ed25519-X","outerTrustAnchorSha256","TrustAnchorPinV2")
_SNAPSHOT_CONTROL_DISPATCH=(
    ("settlement",("SnapshotTransportSettlementV2",)),
    ("terminal",("SnapshotTransportTerminalV2",)),
)
_row("SnapshotTransportControlEnvelopeV2","X",bodies=("SnapshotTransportSettlementV2","SnapshotTransportTerminalV2"),
     key="snapshot-control",profile="hmac-X",purposes=("envelope-hash","mac"),
     bindingSha256=Ref("SnapshotTransportBindingV2"),kind=Enum("settlement","terminal"),
     bodySchema=Enum("SnapshotTransportSettlementV2","SnapshotTransportTerminalV2"),
     bodyByteLength=Integer(1,65536),bodySha256=Ref("SnapshotTransportSettlementV2","SnapshotTransportTerminalV2"),
     algorithm=Const("HMAC-SHA256"),keyId=ID,tag=Base64(32),
     rules=(Rule("dispatch-schema-ref",("kind","bodySchema","bodySha256"),_SNAPSHOT_CONTROL_DISPATCH),))

# These are literal closed semantic slots, not advisory tables. A caller cannot
# delete, widen, duplicate, or replace one while retaining the adapter-v2 name.
NAMED_EXACT_RULE_CONTRACTS=MappingProxyType({
    "AcquisitionReservationV2":(
        Rule("dispatch-value",("expectedRole","expectedKind"),RESOURCE_ROLE_KIND_TABLE),),
    "AcquisitionStateV2":(
        Rule("dispatch-value",("resourceRole","resourceKind"),RESOURCE_ROLE_KIND_TABLE),
        Rule("dispatch-value",("resourceRole","closureProofKind"),RESOURCE_ROLE_CLOSURE_TABLE),),
    "SupervisorClosureBodyV2":(
        Rule("not-constant-if",("servicePredecessorKind","serviceTerminalOutcome"),
             ("terminal-present","missing")),
        Rule("envelope-body-field-equal",
             ("serviceTerminalEnvelopeSha256","serviceTerminalOutcome"),
             ("ServiceTerminalEnvelopeV2","ServiceTerminalBodyV2","outcome"))),
    "ControlEnvelopeV2":(
        Rule("dispatch-schema-ref",("kind","bodySchema","bodySha256"),_CONTROL_DISPATCH),),
    "AckControlEnvelopeV2":(
        Rule("dispatch-schema-ref",("kind","bodySchema","bodySha256"),_ACK_CONTROL_DISPATCH),),
    "SnapshotTransportControlEnvelopeV2":(
        Rule("dispatch-schema-ref",("kind","bodySchema","bodySha256"),_SNAPSHOT_CONTROL_DISPATCH),),
})
NAMED_BODY_DISPATCH_FINGERPRINTS=MappingProxyType({
    "ControlEnvelopeV2":"a123697f04fe017554ba36581e9c06bac2465b00ff852cbc6f7d06ca7f393f5d",
    "AckControlEnvelopeV2":"2ec03fda827b07d250136469cb26851a4bc8810f7bdf87010c4e3a91101e6e72",
    "SnapshotTransportControlEnvelopeV2":"efc20b4dee9b93e5c8565b38a50770354bfac415ee8e071a1aef14fc2b55b5df",
})

def _fixture_measure(value):
    """Return canonical encoded length and exact encoder node charge."""
    if value is None: return 4,1
    if type(value) is bool: return (4 if value else 5),1
    if type(value) is int: return len(str(value)),1
    if type(value) is str: return len(_string(value).encode("utf-8")),1
    if type(value) is list:
        parts=[_fixture_measure(x) for x in value]
        return 2+max(0,len(parts)-1)+sum(x[0] for x in parts),1+sum(x[1] for x in parts)
    if type(value) is dict:
        parts=[(_fixture_measure(k),_fixture_measure(v)) for k,v in value.items()]
        return 2+max(0,len(parts)-1)+sum(k[0]+1+v[0] for k,v in parts),1+len(parts)+sum(v[1] for k,v in parts)
    _reject("fixture type")


def _fixture_scalar(member,path,registry,maximum=True):
    kind,a=member.kind,member.args
    if kind=="const": return a[0]
    if kind=="enum": return max(a,key=lambda x:(len(canonical(x)),x))
    if kind=="schema-name": return max(registry,key=lambda x:(len(x),x))
    if kind=="integer": return max(a,key=lambda x:(len(str(x)),x))
    if kind=="decimal": return str(max(a,key=lambda x:(len(str(x)),x)))
    if kind in ("hash","ref"): return hashlib.sha256(path.encode()).hexdigest()
    if kind=="boolean": return False
    if kind=="base64": return base64.b64encode(bytes(a[0])).decode()
    if kind=="text":
        if a[1]=="path": return "/"+"x"*(a[0]-1)
        if a[1]=="uri": return "file:///"+"x"*(a[0]-8)
        return ("\x01" if a[1] in ("nfc","ascii") else "x")*a[0]
    _reject("not scalar")


def _fixture_finite_values(member,triggers,path,registry):
    """Finite semantic equivalence representatives for one scalar field."""
    nullable=member.kind=="nullable"
    base=member.args[0] if nullable else member
    if base.kind=="enum": values=list(base.args)
    elif base.kind=="boolean": values=[False,True]
    elif base.kind=="const": values=[base.args[0]]
    elif base.kind in ("integer","decimal"):
        maximum=_fixture_scalar(base,path,registry)
        values=[maximum]
    else:
        values=[_fixture_scalar(base,path,registry)]
    values.extend(x for x in triggers if x is not None)
    if nullable: values.insert(0,None)
    result=[];seen=set()
    for value in values:
        encoded=canonical(value)
        if encoded not in seen:
            seen.add(encoded);result.append(value)
    return tuple(result)


def _fixture_semantic_assignments(spec,registry,path):
    """Jointly enumerate every finite discriminator used by current rules."""
    fields=dict(spec.fields); triggers={}
    first_field_rules={"mask","mask-in","constant-if","not-constant-if",
        "nonnull-constant","vector-range-if","numeric-range-if",
        "reference-dispatch","dispatch-schema-ref","dispatch-ref","dispatch-value"}
    for rule in spec.rules:
        if rule.kind in first_field_rules:
            key=rule.fields[0];bucket=triggers.setdefault(key,[])
            if rule.kind=="mask": bucket.append(rule.args[0])
            elif rule.kind=="mask-in": bucket.extend(rule.args[0])
            elif rule.kind in ("constant-if","not-constant-if","vector-range-if","numeric-range-if"):
                bucket.append(rule.args[0])
            elif rule.kind in ("reference-dispatch","dispatch-schema-ref","dispatch-ref","dispatch-value"):
                bucket.extend(entry[0] for entry in rule.args)
        elif rule.kind=="evidence-map":
            triggers.setdefault(rule.fields[0],[])
            triggers.setdefault(rule.fields[1],[])
        elif rule.kind=="slot-token":
            triggers.setdefault(rule.fields[0],[]).extend(range(len(AUTH_TOKENS)))
        elif rule.kind=="clock-xor":
            triggers.setdefault(rule.fields[0],[])
    # Keep a field even when another discriminator derives it: nullable coupled
    # targets can select a distinct valid arm before derivation (for example,
    # an uncertain acquisition has no closure proof). The Cartesian product is
    # intentional and each candidate starts from the same pristine seed.
    keys=tuple(sorted(triggers))
    domains=tuple(_fixture_finite_values(fields[key],triggers[key],path+"/"+key,registry)
                  for key in keys)
    import itertools
    result=[]
    for parts in itertools.product(*domains):
        assignment=dict(zip(keys,parts));consistent=True
        for rule in spec.rules:
            f,a=rule.fields,rule.args
            if rule.kind=="dispatch-value" and f[0] in assignment and f[1] in assignment:
                consistent=assignment[f[1]] is None or assignment[f[1]]==dict(a)[assignment[f[0]]]
            elif rule.kind=="nonnull-constant" and f[0] in assignment and f[1] in assignment:
                consistent=assignment[f[0]] is None or assignment[f[1]]==a[0]
            elif rule.kind=="constant-if" and f[0] in assignment and f[1] in assignment and assignment[f[0]]==a[0]:
                consistent=assignment[f[1]]==a[1]
            elif rule.kind=="not-constant-if" and f[0] in assignment and f[1] in assignment and assignment[f[0]]==a[0]:
                consistent=assignment[f[1]]!=a[1]
            elif rule.kind=="mask" and f[0] in assignment and assignment[f[0]]==a[0]:
                consistent=(all(key not in assignment or assignment[key] is not None for key in a[1]) and
                            all(key not in assignment or assignment[key] is None for key in a[2]))
            if not consistent: break
        if consistent: result.append(assignment)
    return tuple(result)


def _fixture_apply_rules(spec,value,registry,make):
    fields=dict(spec.fields)
    if spec.phase=="X":
        # A prior arm can erase contextual references. Restore the selected
        # context before applying the new arm's rules, never relax its mask.
        value["contextPhase"]="post-E"
        for key in ("planCoreSha256","executionBindingSha256"):
            if value[key] is None:
                value[key]=make(fields[key].args[0],spec.name+"/"+key)
    for _ in range(3):
        for rule in spec.rules:
            f,a=rule.fields,rule.args
            if rule.kind=="length": value[f[0]]=len(value[f[1]])
            elif rule.kind=="equal":
                for target in f[1:]: value[target]=value[f[0]]
            elif rule.kind=="advance-one":
                v=int(value[f[0]])+1
                value[f[1]]=str(v) if fields[f[1]].kind=="decimal" else v
            elif rule.kind=="less":
                if int(value[f[0]])>=int(value[f[1]]):
                    v=int(value[f[1]])-1
                    value[f[0]]=str(v) if fields[f[0]].kind=="decimal" else v
            elif rule.kind=="range": value[f[0]]=min(value[f[0]],value[f[1]])
            elif rule.kind=="sum": value[f[0]]=value[f[1]]+value[f[2]]
            elif rule.kind=="mask" and value[f[0]]==a[0]:
                for key in a[1]:
                    if value[key] is None: value[key]=make(fields[key].args[0],spec.name+"/"+key)
                for key in a[2]: value[key]=None
            elif rule.kind=="constant-if" and value[f[0]]==a[0]: value[f[1]]=a[1]
            elif rule.kind=="not-constant-if" and value[f[0]]==a[0] and value[f[1]]==a[1]:
                candidates=[candidate for candidate in _fixture_finite_values(fields[f[1]],(),spec.name+"/"+f[1],registry)
                            if candidate!=a[1]]
                if not candidates: _reject("not-constant-if fixture domain")
                value[f[1]]=max(candidates,key=lambda x:(_fixture_measure(x)[0],canonical(x)))
            elif rule.kind=="nonnull-constant" and value[f[0]] is not None: value[f[1]]=a[0]
            elif rule.kind=="nullable-pair":
                if any(value[key] is None for key in f):
                    for key in f: value[key]=None
            elif rule.kind=="clock-xor":
                if value[f[0]] is None:
                    value[f[1]]=make(fields[f[1]].args[0],spec.name+"/"+f[1])
                else:
                    value[f[1]]=None
            elif rule.kind=="unique":
                member=fields[f[0]].args[0]
                if member.kind=="integer":
                    count=len(value[f[0]])
                    if member.args[1]-member.args[0]+1<count: _reject("unique fixture capacity")
                    value[f[0]]=[member.args[1]-i for i in range(count)]
                elif member.kind in ("hash","ref"):
                    value[f[0]]=[hashlib.sha256((spec.name+"/"+f[0]+"/"+str(i)).encode()).hexdigest()
                                 for i in range(len(value[f[0]]))]
            elif rule.kind=="ordered": value[f[0]]=sorted(value[f[0]])
            elif rule.kind=="field-schema":
                value[f[0]]=value[f[1]]["authority"].removeprefix(PREFIX+"schema/")
            elif rule.kind=="dispatch-schema-ref":
                if value[f[1]] is not None or value[f[2]] is not None:
                    allowed=dict(a)[value[f[0]]]
                    value[f[1]]=max(allowed,key=lambda x:(len(x),x))
                    if value[f[2]] is None: value[f[2]]=make(fields[f[2]].args[0],spec.name+"/"+f[2])
            elif rule.kind=="dispatch-value":
                if value[f[1]] is not None: value[f[1]]=dict(a)[value[f[0]]]
            elif rule.kind=="object-field-equal": value[f[0]]=value[f[1]][a[0]]
            elif rule.kind=="mask-in" and value[f[0]] in a[0]:
                for key in a[1]:
                    if value[key] is None: value[key]=make(fields[key].args[0],spec.name+"/"+key)
                for key in a[2]: value[key]=None
            elif rule.kind=="vector-range-if" and value[f[0]]==a[0]:
                member=fields[f[1]].args[0]
                while len(value[f[1]])<a[1]: value[f[1]].append(make(member,spec.name+"/"+f[1]+"/"+str(len(value[f[1]]))))
                del value[f[1]][a[2]:]
            elif rule.kind=="numeric-range-if" and value[f[0]]==a[0]:
                value[f[1]]=max(a[1],min(a[2],value[f[1]]))
            elif rule.kind=="keyed-complete":
                member=fields[f[0]].args[0]; expected=a[1]
                value[f[0]]=[make(member,spec.name+"/"+f[0]+"/"+str(i)) for i in range(len(expected))]
                for item,key_values in zip(value[f[0]],expected):
                    for key,key_value in zip(a[0],key_values): item[key]=key_value
            elif rule.kind=="keyed-order":
                key_fields=a[0]
                for index,item in enumerate(value[f[0]]):
                    for key in key_fields:
                        member=dict(registry[item["authority"].removeprefix(PREFIX+"schema/")].fields)[key]
                        if member.kind=="integer": item[key]=member.args[0]+index
                        elif member.kind in ("hash","ref"):
                            item[key]=hashlib.sha256((spec.name+"/"+f[0]+"/"+key+"/"+str(index)).encode()).hexdigest()
                        elif member.kind=="text":
                            width=member.args[0]
                            suffix=("%08d"%index)
                            if member.args[1]=="path": item[key]="/"+"x"*(width-1-len(suffix))+suffix
                            elif member.args[1] in ("token","ascii","nfc"): item[key]="x"*(width-len(suffix))+suffix
                value[f[0]]=sorted(value[f[0]],key=lambda item:tuple(item[key] for key in key_fields))
            elif rule.kind=="contiguous-index":
                for index,item in enumerate(value[f[0]]): item[a[0]]=a[1]+index
            elif rule.kind=="parallel-projection": value[f[1]]=[item[a[0]] for item in value[f[0]]]
            elif rule.kind=="all-flag": value[f[1]]=all(item[a[0]] is True for item in value[f[0]])
            elif rule.kind=="slot-token": value[f[1]]=AUTH_TOKENS[value[f[0]]]
            elif rule.kind=="evidence-map":
                phase,map_kind=value[f[0]],value[f[1]]
                start=0 if phase=="before" else 12
                count=11 if map_kind=="prior-seal" else 12
                member=fields[f[4]].args[0]
                value[f[4]]=[make(member,spec.name+"/"+f[4]+"/"+str(i)) for i in range(count)]
                for index,item in enumerate(value[f[4]]):
                    item["slot"]=start+index;item["operationToken"]=AUTH_TOKENS[start+index]
                value[f[2]]=start if count else None; value[f[3]]=start+count-1 if count else None
    if spec.phase=="X":
        if value["contextPhase"]=="pre-plan":
            value["planCoreSha256"]=None;value["executionBindingSha256"]=None
        elif value["contextPhase"]=="pre-E": value["executionBindingSha256"]=None
    return value


def maximum_fixture(name,registry):
    """Generate an admitted maximum-size codec fixture with a checked proof class.

    A class-saturated fixture proves the enforced encoded maximum. An unconstrained
    field-extremum is exact when its complete grammar/rule extrema fit. The sole
    joint node-budget acquisition-vector case is optimized over both maximal
    state arms and every allowed vector cardinality. No fixture authenticates refs.
    """
    import copy
    import itertools
    cache={}
    def build(schema_name,path):
        if schema_name in cache:
            value,proof=cache[schema_name]
            return copy.deepcopy(value),proof
        spec=registry[schema_name]
        def make(member,where):
            kind,a=member.kind,member.args
            if kind=="nullable":
                present=make(a[0],where)
                return max((None,present),key=lambda x:(_fixture_measure(x)[0],canonical(x)))
            if kind in ("object","choice"):
                candidates=[build(target,where)[0] for target in a]
                return max(candidates,key=lambda x:_fixture_measure(x)[0])
            if kind=="vector":
                return [make(a[0],where+"/"+str(i)) for i in range(a[2])]
            if kind=="tuple":
                return [make(t,where+"/"+str(i)) for i,t in enumerate(a)]
            return _fixture_scalar(member,where,registry)
        # Distinguish complete vector objects without changing encoded widths.
        def stamp(member,item,prefix):
            if member.kind=="nullable":
                if item is not None: stamp(member.args[0],item,prefix)
            elif member.kind in ("object","choice"):
                row=registry[item["authority"].removeprefix(PREFIX+"schema/")]
                for key,t in row.fields:
                    if t.kind in ("hash","ref"): item[key]=hashlib.sha256((prefix+"/"+key).encode()).hexdigest()
                    else: stamp(t,item[key],prefix+"/"+key)
            elif member.kind=="vector":
                for i,x in enumerate(item): stamp(member.args[0],x,prefix+"/"+str(i))
            elif member.kind=="tuple":
                for i,(t,x) in enumerate(zip(member.args,item)): stamp(t,x,prefix+"/"+str(i))
        pristine={k:make(t,path+"/"+k) for k,t in spec.fields}
        # AcquisitionSnapshotBodyV2 is the one schema whose declared vector
        # cardinality can exceed the codec's global structural-node limit.  A
        # 512-row seed cannot even be canonically inspected, so start that
        # schema at the empty admitted cardinality and solve its finite
        # cardinality/arm/node-budget problem below.
        if schema_name=="AcquisitionSnapshotBodyV2":
            pristine["states"]=[]
            pristine["stateCount"]=0
        if spec.phase=="X":
            pristine["contextPhase"]="post-E"
        best=None;best_key=None;candidate_errors=[]
        for assignment in _fixture_semantic_assignments(spec,registry,path):
            candidate=copy.deepcopy(pristine)
            candidate.update(assignment)
            try:
                _fixture_apply_rules(spec,candidate,registry,make)
                for key,t in spec.fields: stamp(t,candidate[key],path+"/"+key)
                _fixture_apply_rules(spec,candidate,registry,make)
                _validate_value(schema_name,candidate,registry)
            except ContractError as error:
                # Fixture construction may deliberately begin above a schema's
                # byte class so the later exact-cap trimming pass can preserve
                # vector/cardinality maxima.  `_validate_value` performs the
                # byte-class check only after every type and semantic rule, so
                # this exact terminal error is safe to defer; no other error is.
                if str(error)!=schema_name+": encoded class":
                    candidate_errors.append(str(error))
                    continue
            candidate_size,candidate_nodes=_fixture_measure(candidate)
            if candidate_nodes>32768:
                continue
            candidate_key=(candidate_size,canonical(candidate))
            if best_key is None or candidate_key>best_key:
                best,best_key=candidate,candidate_key
        if best is None:
            detail=(" ("+candidate_errors[-1]+")") if candidate_errors else ""
            _reject("maximum fixture has no admitted arm: "+schema_name+detail)
        value=best
        for key,t in spec.fields: stamp(t,value[key],path+"/"+key)
        _fixture_apply_rules(spec,value,registry,make)
        size,nodes=_fixture_measure(value)
        proof="field-and-arm-extremum"
        if schema_name=="AcquisitionSnapshotBodyV2":
            # Enumerate every admitted AcquisitionState discriminator tuple
            # from a pristine seed.  Group identical byte/node profiles and
            # discard only profiles dominated on both dimensions.  The DP
            # below is then exhaustive over every remaining state arm and all
            # 0..512 cardinalities under the single global structural budget.
            state_spec=registry["AcquisitionStateV2"]
            state_fields=dict(state_spec.fields)
            state_seed={k:make(t,path+"/states/arm/"+k) for k,t in state_spec.fields}
            state_seed["contextPhase"]="post-E"
            profiles={}
            for assignment in _fixture_semantic_assignments(state_spec,registry,path+"/states/arm"):
                candidate=copy.deepcopy(state_seed);candidate.update(assignment)
                # Ordinal width is accounted for as a cardinality-only term;
                # normalize it here so arm costs remain directly comparable.
                candidate["acquisitionOrdinal"]=0
                try:
                    _fixture_apply_rules(state_spec,candidate,registry,make)
                    for key,t in state_spec.fields:
                        stamp(t,candidate[key],path+"/states/arm/"+key)
                    _fixture_apply_rules(state_spec,candidate,registry,make)
                    candidate["acquisitionOrdinal"]=0
                    _validate_value("AcquisitionStateV2",candidate,registry)
                except ContractError:
                    continue
                arm_size,arm_nodes=_fixture_measure(candidate)
                arm_key=(arm_size,arm_nodes)
                previous=profiles.get(arm_key)
                if previous is None or canonical(candidate)>canonical(previous):
                    profiles[arm_key]=candidate
            arms=[]
            for (arm_size,arm_nodes),candidate in profiles.items():
                dominated=any((other_nodes<=arm_nodes and other_size>=arm_size and
                    (other_nodes<arm_nodes or other_size>arm_size))
                    for other_size,other_nodes in profiles if
                    (other_size,other_nodes)!=(arm_size,arm_nodes))
                if not dominated:
                    arms.append((arm_size,arm_nodes,canonical(candidate),candidate))
            arms.sort(key=lambda row:(-row[0],row[1],row[2]))
            if not arms:
                _reject("maximum fixture has no admitted acquisition-state arm")

            value["states"]=[];value["stateCount"]=0
            _fixture_apply_rules(spec,value,registry,make)
            base_size,base_nodes=_fixture_measure(value)
            # levels[n][nodes] = (sum-of-normalized-arm-bytes,
            #                     predecessor-nodes, chosen-arm-index)
            levels=[{0:(0,None,None)}]
            winner=(base_size,0,0)
            cap=SIZE_CLASSES[spec.size_class]
            for count in range(1,513):
                previous=levels[-1];current={}
                for used_nodes,(used_bytes,_prior,_arm) in previous.items():
                    for arm_index,(arm_size,arm_nodes,_encoded,_candidate) in enumerate(arms):
                        new_nodes=used_nodes+arm_nodes
                        if base_nodes+new_nodes>32768:
                            continue
                        new_bytes=used_bytes+arm_size
                        retained=current.get(new_nodes)
                        if retained is None or new_bytes>retained[0]:
                            current[new_nodes]=(new_bytes,used_nodes,arm_index)
                levels.append(current)
                if not current:
                    break
                ordinal_growth=sum(len(str(index))-1 for index in range(count))
                count_growth=len(str(count))-1
                commas=count-1
                for used_nodes,(used_bytes,_prior,_arm) in current.items():
                    total=base_size+used_bytes+ordinal_growth+count_growth+commas
                    if total<=cap and total>winner[0]:
                        winner=(total,count,used_nodes)
            _total,count,cursor=winner
            selections=[]
            for level in range(count,0,-1):
                _bytes,prior,arm_index=levels[level][cursor]
                selections.append(arm_index);cursor=prior
            selections.reverse()
            value["states"]=[copy.deepcopy(arms[index][3]) for index in selections]
            value["stateCount"]=count
            stamp(dict(spec.fields)["states"],value["states"],path+"/states")
            _fixture_apply_rules(spec,value,registry,make)
            size,nodes=_fixture_measure(value)
            if size!=winner[0]:
                _reject("acquisition snapshot DP size accounting")
            proof="exhaustive-cardinality-state-arm-node-budget"
        if nodes>32768:
            _reject("maximum fixture unresolved node budget: "+schema_name+" "+str(nodes))
        cap=SIZE_CLASSES[spec.size_class]
        if size>cap:
            # A canonical path/token/URI has one-byte slack; preserve all vector
            # maxima and trim only declared string lengths to reach the exact cap.
            slack=[]
            def shorten(member,item,parent,key):
                nonlocal size
                if size<=cap: return
                kind,a=member.kind,member.args
                if kind=="nullable":
                    if item is not None: shorten(a[0],item,parent,key)
                elif kind in ("object","choice"):
                    nested=registry[item["authority"].removeprefix(PREFIX+"schema/")]
                    for k,t in nested.fields: shorten(t,item[k],item,k)
                elif kind=="vector":
                    for i,x in enumerate(item): shorten(a[0],x,item,i)
                elif kind=="tuple":
                    for i,(t,x) in enumerate(zip(a,item)): shorten(t,x,item,i)
                elif kind=="text":
                    if a[1] in ("path","uri","token"):
                        minimum={"path":2,"uri":9,"token":1}[a[1]]
                        reduction=min(size-cap,max(0,len(item)-minimum))
                        if reduction:
                            parent[key]=item[:-reduction];size-=reduction
                            slack.append((parent,key,a[0]))
                    elif a[1] in ("nfc","ascii"):
                        old=len(_string(item).encode("utf-8"))-2
                        target=max(1,old-(size-cap))
                        while target>0:
                            c=min(a[0],target//6);plain=target-6*c
                            if c+plain<=a[0]:
                                replacement="\x01"*c+"x"*plain
                                parent[key]=replacement;size-=old-target
                                break
                            target-=1
            for key,t in spec.fields: shorten(t,value[key],value,key)
            for parent,key,limit in slack:
                growth=min(cap-size,limit-len(parent[key]))
                if growth>0: parent[key]+="x"*growth;size+=growth
            if size!=cap: _reject("maximum fixture unresolved encoded budget: "+schema_name)
            proof="encoded-class-saturated"
        _validate_value(schema_name,value,registry)
        raw=canonical(value)
        if len(raw)!=size: _reject("fixture size accounting")
        cache[schema_name]=(copy.deepcopy(value),proof)
        return value,proof
    return build(name,name)


def maximum_fixture_corpus(registry):
    result=[]
    for name,spec in registry.items():
        value,proof=maximum_fixture(name,registry)
        raw=canonical(value)
        result.append({"schema":name,"sizeClass":spec.size_class,
            "encodedMaximum":len(raw),"classLimit":SIZE_CLASSES[spec.size_class],
            "rawSha256":hashlib.sha256(raw).hexdigest(),"maximumProof":proof})
    return tuple(result)

def wire_limit(name,registry):
    spec=require_schema(name,registry)
    if not spec.envelope_bodies: return SIZE_CLASSES[spec.size_class]
    return 12+SIZE_CLASSES[spec.size_class]+max(wire_limit(body,registry) for body in spec.envelope_bodies)


def decode_wire(name,raw,registry):
    """Decode one canonical body or one exact detached-envelope frame, recursively."""
    spec=require_schema(name,registry)
    if type(raw) is not bytes or not 1<=len(raw)<=wire_limit(name,registry):
        _reject("wire type/size")
    if not spec.envelope_bodies:
        return validate_body(name,raw,registry),None
    if len(raw)<12: _reject("envelope short prefix")
    n=int.from_bytes(raw[:4],"big")
    if not 1<=n<=SIZE_CLASSES[spec.size_class] or len(raw)<4+n+8:
        _reject("envelope metadata bounds")
    metadata_raw=raw[4:4+n]
    value=validate_body(name,metadata_raw,registry)
    body_length=int.from_bytes(raw[4+n:12+n],"big")
    if body_length!=value["bodyByteLength"] or len(raw)!=12+n+body_length:
        _reject("envelope raw-body length/trailing")
    body=raw[12+n:]
    target=value["bodySchema"]
    if target not in spec.envelope_bodies: _reject("envelope body target")
    body_value,_=decode_wire(target,body,registry)
    if wire_digest(target,body,registry)!=value["bodySha256"]:
        _reject("envelope typed body digest")
    for field in ("constructionId","contextPhase","planCoreSha256","executionBindingSha256"):
        if field in body_value and field in value and body_value[field]!=value[field]:
            _reject("envelope/body context mismatch")
    if name=="ExecutionAttestationEnvelopeV2" and value["executionBindingSha256"]!=value["bodySha256"]:
        _reject("execution external E mismatch")
    return value,body


def wire_digest(name,raw,registry):
    spec=require_schema(name,registry)
    if not spec.envelope_bodies: return body_digest(name,raw,registry)
    value,body=decode_wire(name,raw,registry)
    metadata=canonical(value)
    return hashlib.sha256(ld(domain(name,"envelope-hash",registry),(metadata,body))).hexdigest()


def envelope_frame(name,metadata,body,registry):
    spec=require_schema(name,registry)
    if not spec.envelope_bodies: _reject("not envelope")
    raw=canonical(metadata)
    result=len(raw).to_bytes(4,"big")+raw+len(body).to_bytes(8,"big")+body
    decode_wire(name,result,registry)
    return result


def authentication_input(name,metadata_raw,body,registry):
    """Exact preimage only. Supplying bytes/keys never proves OS provenance."""
    spec=require_schema(name,registry)
    if not spec.envelope_bodies: _reject("not authenticated envelope")
    value=validate_body(name,metadata_raw,registry)
    envelope_frame(name,value,body,registry)
    key_fields=[key for key in ("signingKeyId","supervisorSigningKeyId","keyId") if key in value]
    if len(key_fields)!=1: _reject("ambiguous key ID")
    kid=value[key_fields[0]].encode("ascii")
    def h(field): return bytes.fromhex(value[field]) if value.get(field) is not None else b""
    profile=spec.signature_profile
    if profile.endswith("-X"):
        context=(h("constructionId"),value["contextPhase"].encode("ascii"),h("planCoreSha256"),h("executionBindingSha256"))
    elif profile=="ed25519-N": context=(h("constructionId"),)
    elif profile=="ed25519-P": context=(h("planCoreSha256"),)
    else: context=(h("planCoreSha256"),h("executionBindingSha256"))
    extra=()
    if profile=="hmac-settlement": extra=(h("dataEndpointBindingSha256"),h("ackControlBindingSha256"))
    elif profile=="hmac-guardian-hop": extra=(h("hopBindingSha256"),)
    elif profile=="hmac-guardian-control":
        extra=(h("streamReservationSha256"),h("hopBindingSha256"),value["direction"].encode(),
            value["controlClass"].encode(),value["controlSequence"].to_bytes(8,"big"))
    elif profile=="hmac-ack-control":
        extra=(h("ackControlBindingSha256"),value["direction"].encode(),value["sequenceClass"].encode(),
            value["messageSequence"].to_bytes(8,"big"),h("previousEnvelopeSha256"),value["kind"].encode())
    elif profile=="hmac-X": extra=(h("bindingSha256"),value["kind"].encode())
    parts=context+extra+(kid,h("bodySha256"),len(body).to_bytes(8,"big"),body)
    purpose="signature" if profile.startswith("ed25519") else "mac"
    return ld(domain(name,purpose,registry),parts)


def verify_envelope(name,raw,key,expected_key_id,registry):
    """Verify under an explicitly supplied retained trust key, not ambient trust."""
    import hmac
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if type(key) is not bytes or len(key)!=32 or type(expected_key_id) is not str:
        _reject("verification key type/length")
    spec=require_schema(name,registry)
    value,body=decode_wire(name,raw,registry)
    if body is None: _reject("body is not signature authority")
    keys=[field for field in ("signingKeyId","supervisorSigningKeyId","keyId") if field in value]
    if len(keys)!=1 or value[keys[0]]!=expected_key_id: _reject("verification key ID")
    message=authentication_input(name,canonical(value),body,registry)
    try:
        if spec.signature_profile.startswith("ed25519"):
            Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(value["signature"]),message)
        elif not hmac.compare_digest(hmac.digest(key,message,"sha256"),base64.b64decode(value["tag"])):
            _reject("MAC rejected")
    except InvalidSignature as error:
        raise ContractError("signature rejected") from error
    return value


def _bind_envelope_body_dispatch(spec,value,body_name):
    """Bind every body-schema dispatch discriminator to one unambiguous arm."""
    dispatchers=tuple(rule for rule in spec.rules if
        rule.kind=="dispatch-schema-ref" and
        rule.fields[1:]==("bodySchema","bodySha256"))
    required=tuple(rule for rule in NAMED_EXACT_RULE_CONTRACTS.get(spec.name,()) if
        rule.kind=="dispatch-schema-ref" and
        rule.fields[1:]==("bodySchema","bodySha256"))
    if required and dispatchers!=required:
        _reject(spec.name+": required body dispatcher missing or changed")
    for rule in dispatchers:
        matches=tuple(discriminator for discriminator,targets in rule.args
                      if body_name in targets)
        if len(matches)!=1:
            _reject(spec.name+": body dispatch is absent or ambiguous for "+body_name)
        value[rule.fields[0]]=matches[0]
    return value


def maximum_wire_fixture(name,registry):
    spec=require_schema(name,registry)
    if not spec.envelope_bodies:
        value,proof=maximum_fixture(name,registry)
        return canonical(value),proof
    candidates=[]
    for body_name in spec.envelope_bodies:
        body,proof=maximum_wire_fixture(body_name,registry)
        body_value,_=decode_wire(body_name,body,registry)
        value,_=maximum_fixture(name,registry)
        value["bodySchema"]=body_name;value["bodyByteLength"]=len(body)
        value["bodySha256"]=wire_digest(body_name,body,registry)
        # Replacing the independently generated maximum body also replaces the
        # semantic message arm. Retaining the unrelated maximum discriminator
        # would create a structurally valid but semantically false fixture.
        _bind_envelope_body_dispatch(spec,value,body_name)
        for field in ("constructionId","contextPhase","planCoreSha256","executionBindingSha256"):
            if field in value and field in body_value: value[field]=body_value[field]
        if name=="ExecutionAttestationEnvelopeV2": value["executionBindingSha256"]=value["bodySha256"]
        candidates.append(envelope_frame(name,value,body,registry))
    return max(candidates,key=lambda x:(len(x),x)),"exhaustive-body-pairing-wire-maximum"


def _validate_graph_bound_rules(name,value,index,registry,path=None):
    """Validate every discriminator/ref join, including inline object trees."""
    location=name if path is None else path
    spec=registry[name]
    for rule in spec.rules:
        if rule.kind=="dispatch-ref":
            discriminator,reference=(value[field] for field in rule.fields)
            allowed=dict(rule.args).get(discriminator)
            if (allowed is None or reference is None or reference not in index or
                    index[reference][0] not in allowed):
                _reject(location+": graph-bound dispatch-ref target")
        elif rule.kind=="dispatch-schema-ref":
            discriminator,declared,reference=(value[field] for field in rule.fields)
            allowed=dict(rule.args).get(discriminator)
            if (declared is None)!=(reference is None):
                _reject(location+": graph-bound dispatch schema/ref nullability")
            if declared is None:
                if allowed is None:
                    _reject(location+": graph-bound dispatch discriminator")
                continue
            if (allowed is None or declared not in allowed or reference not in index or
                    index[reference][0]!=declared):
                _reject(location+": graph-bound dispatch-schema-ref target")
        elif rule.kind=="envelope-body-field-equal":
            reference=value[rule.fields[0]]
            if reference is None: continue
            envelope_name,body_name,body_field=rule.args
            if reference not in index or index[reference][0]!=envelope_name:
                _reject(location+": graph-bound envelope reference")
            envelope_value,body_raw=decode_wire(envelope_name,index[reference][1],registry)
            if body_raw is None or envelope_value["bodySchema"]!=body_name:
                _reject(location+": graph-bound envelope body")
            body_value,_=decode_wire(body_name,body_raw,registry)
            if value[rule.fields[1]]!=body_value[body_field]:
                _reject(location+": graph-bound envelope body field mismatch")

    def descend(member,child,child_path):
        kind,args=member.kind,member.args
        if kind=="nullable":
            if child is not None: descend(args[0],child,child_path)
        elif kind in ("object","choice"):
            target=child["authority"].removeprefix(PREFIX+"schema/")
            _validate_graph_bound_rules(target,child,index,registry,child_path)
        elif kind=="vector":
            for ordinal,item in enumerate(child):
                descend(args[0],item,child_path+"/"+str(ordinal))
        elif kind=="tuple":
            for ordinal,(item_type,item) in enumerate(zip(args,child)):
                descend(item_type,item,child_path+"/"+str(ordinal))
    for field,member in spec.fields:
        descend(member,value[field],location+"/"+field)


def reference_graph(records,registry):
    """Closed typed reference DAG. This is distinct from signature/OS admission."""
    if type(records) is not tuple or not records: _reject("reference graph tuple")
    index={};values={}
    for record in records:
        if type(record) is not tuple or len(record)!=2 or type(record[0]) is not str or type(record[1]) is not bytes:
            _reject("reference record type")
        name,raw=record
        value,_=decode_wire(name,raw,registry)
        digest=wire_digest(name,raw,registry)
        if digest in index: _reject("duplicate reference record")
        index[digest]=(name,raw);values[digest]=value
    graph={}
    for digest,(name,raw) in index.items():
        edges=[]
        def scan(member,value):
            kind,a=member.kind,member.args
            if kind=="nullable":
                if value is not None: scan(a[0],value)
            elif kind=="ref":
                if value not in index or index[value][0] not in a: _reject("missing/wrong typed reference")
                edges.append(value)
            elif kind in ("object","choice"):
                target=value["authority"].removeprefix(PREFIX+"schema/")
                for key,t in registry[target].fields: scan(t,value[key])
            elif kind=="vector":
                for child in value: scan(a[0],child)
            elif kind=="tuple":
                for t,child in zip(a,value): scan(t,child)
        for key,member in registry[name].fields: scan(member,values[digest][key])
        _validate_graph_bound_rules(name,values[digest],index,registry)
        graph[digest]=tuple(sorted(set(edges)))
    return validate_dependency_dag(graph)


def snapshot_chunk_frame(header_raw,payload,key,registry):
    """Detached chunk framing only; no acquisition, clock or replay authority."""
    import hmac
    if type(key) is not bytes or len(key)!=32 or type(payload) is not bytes:
        _reject("snapshot frame key/payload type")
    header=validate_body("SnapshotTransportChunkV2",header_raw,registry)
    if (not 1<=len(payload)<=65536 or header["chunkByteLength"]!=len(payload)
            or header["chunkSha256"]!=hashlib.sha256(payload).hexdigest()
            or header["offset"]+len(payload)>2101761):
        _reject("snapshot payload binding")
    message=ld(domain("SnapshotTransportChunkV2","frame-mac",registry),(header_raw,payload))
    return (len(header_raw).to_bytes(4,"big")+header_raw+
            len(payload).to_bytes(4,"big")+payload+hmac.digest(key,message,"sha256"))


def verify_snapshot_chunk(frame,key,expected_header_raw,registry):
    """Check exact pre-admitted header plus bytes; caller owns one-shot cursor."""
    import hmac
    if type(frame) is not bytes or not 41<=len(frame)<=69672:
        _reject("snapshot frame bound")
    if type(expected_header_raw) is not bytes:
        _reject("snapshot expected header type")
    n=int.from_bytes(frame[:4],"big")
    if not 1<=n<=4096 or len(frame)<8+n+32:
        _reject("snapshot header bound")
    header_raw=frame[4:4+n]
    if header_raw!=expected_header_raw:
        _reject("snapshot retained header mismatch")
    size=int.from_bytes(frame[4+n:8+n],"big")
    if not 1<=size<=65536 or len(frame)!=8+n+size+32:
        _reject("snapshot payload frame length")
    payload=frame[8+n:8+n+size]
    expected=snapshot_chunk_frame(header_raw,payload,key,registry)
    if not hmac.compare_digest(frame,expected):
        _reject("snapshot frame MAC")
    return payload


LOW_ORDER_X25519 = (
    "00"*32,"01"+"00"*31,
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ec"+"ff"*30+"7f","ed"+"ff"*30+"7f","ee"+"ff"*30+"7f",
)


def checked_x25519(private_bytes,peer_public_bytes):
    import hmac
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
    if type(private_bytes) is not bytes or len(private_bytes)!=32 or type(peer_public_bytes) is not bytes or len(peer_public_bytes)!=32:
        _reject("invalid-provenance: X25519 exact length")
    if int.from_bytes(peer_public_bytes,"little") >= (1<<255)-19:
        _reject("invalid-provenance: X25519 noncanonical coordinate")
    try:
        shared=X25519PrivateKey.from_private_bytes(private_bytes).exchange(X25519PublicKey.from_public_bytes(peer_public_bytes))
    except ValueError as error:
        raise ContractError("invalid-provenance: X25519 all-zero shared secret") from error
    if hmac.compare_digest(shared,bytes(32)): _reject("invalid-provenance: X25519 all-zero shared secret")
    return shared

# Capture the reviewed declaration table as immutable primitive tuples. Compiler
# callers cannot alter an envelope policy by replacing a supplied Schema object.
ENVELOPE_CONTRACTS = MappingProxyType({
    item.name:(item.phase,item.key_role,item.signature_profile,item.envelope_bodies,
               tuple(key for key,_ in item.fields))
    for item in _DEFINITIONS if item.envelope_bodies
})
