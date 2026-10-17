# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Deterministic semantic bundle v2 for the BFCL tracks (QV2-06, ADR D1).

v1 (``bfcl_semantic_bundle.py``) stays frozen: the sealed C-ext3 manifest
pins its hash, and its defects are recorded as validity limits
(NEGATIVE_RESULTS §39, §81). A replay of the three spent BFCL sets showed why
v1 refuted the correct tool so often:

* **Contracts authored from the wrong part of the name.** In
  ``Trains_1_FindTrains`` the verb follows a domain prefix and a number. v1
  read only the first and last tokens, so every such tool became a mutating
  ``update``. A "find trains" task was then refuted as a read against a
  write.
* **Dotted names lost their class.** ``game_rewards.get`` kept only ``get``.
* **Verbs and stopwords in the resource lexicon.** "find", "search", "for"
  and "times" were grounded as the requested resource and refuted the tool.
* **Weak read cues against write tools.** "I need a ride" became a read
  request and refuted the ride-booking tool.
* **Negation ignored** (§81): "do not cancel" grounded a cancel request.

The two roles stay separated as in v1. Contract authoring (Role A) reads
only tool metadata: the name and the declared description. Intent
extraction (Role B) reads only the user task and a lexicon derived from the
contracts. Neither sees questions, gold answers or predictions.

Two safety rules are kept from v1 and tightened:

* An unclassifiable tool is a mutating ``update``, never a read.
* When the name and the description disagree about whether a tool writes,
  the writing reading wins. ``RideSharing_2_GetRide`` is named "get" but
  described as "Book a cab", so it is a write.

Development note: this file was designed on the SPENT v3, C-ext2 and C-ext3
sets with ``scripts/bfcl_dev_replay.py``. Numbers from those sets are
development numbers and may not be cited as results. A confirmatory number
needs a sealed set this file has never been run on.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from remora.toolcall.routing.goal_match import EFFECT_VOCABULARY, TaskIntent
from remora.toolcall.routing.tool_contract import (
    ToolContract,
    ToolContractRegistry,
)

BUNDLE_VERSION = "bfcl_semantic_bundle_v2"
USES_DESCRIPTIONS = True
#: The lexicon is built per episode from the tools in scope.
PER_EPISODE_LEXICON = True

# --- Role A vocabulary: verbs as they appear in tool names and descriptions --

#: Verb stems that name a read. Matched against name tokens and the leading
#: verb of the description after a light English inflection strip.
_READ_STEMS = frozenset({
    "get", "find", "list", "search", "show", "lookup", "look", "query",
    "retrieve", "check", "view", "fetch", "read", "display", "return",
    "calculate", "compute", "determine", "estimate", "predict", "count",
    "obtain", "provide", "identify", "detect", "analyze", "analyse",
    "evaluate", "convert", "translate", "summarize", "describe", "explain",
    "verify", "validate", "measure", "recommend", "suggest", "generate",
    "export", "download", "browse", "discover", "explore", "monitor",
    "track", "inspect", "locate", "fetch", "match", "compare", "solve",
    "plot", "visualize", "visualise", "simulate", "forecast",
})
#: Verb stems that name a state change, mapped to the effect family.
_WRITE_STEMS: dict[str, str] = {
    "buy": "create", "purchase": "create", "book": "create", "reserve": "create",
    "add": "create", "create": "create", "schedule": "create", "play": "create",
    "order": "create", "send": "create", "post": "create", "make": "create",
    "register": "create", "submit": "create", "rent": "create", "open": "create",
    "start": "create", "launch": "create", "invite": "create", "upload": "create",
    "insert": "create", "write": "create", "pay": "create", "request": "create",
    "transfer": "update", "update": "update", "change": "update", "set": "update",
    "edit": "update", "modify": "update", "execute": "update", "run": "update",
    "control": "update", "move": "update", "assign": "update", "enable": "update",
    "disable": "update", "toggle": "update", "turn": "update", "adjust": "update",
    "configure": "update", "rename": "update", "replace": "update",
    "cancel": "cancel", "delete": "delete", "remove": "delete", "drop": "delete",
    "close": "close", "approve": "approve",
}
_STOP = frozenset({
    "a", "an", "the", "of", "for", "to", "in", "on", "at", "by", "with", "and",
    "or", "from", "into", "about", "as", "is", "are", "be", "it", "its", "this",
    "that", "these", "those", "given", "specified", "specific", "provided",
    "particular", "certain", "any", "all", "each", "some", "one", "based",
    "user", "users", "using", "use", "via", "per", "if", "such", "their",
    "your", "my", "which", "who", "what", "when", "where", "how", "new",
    "available", "current", "latest", "recent", "details", "detail", "info",
    "information", "data", "list", "api", "value", "values", "number",
    "type", "types", "option", "options", "status", "state", "history",
})


def _stem(word: str) -> str:
    """Light inflection strip: ``retrieves``/``retrieved``/``retrieving``."""
    w = word.lower()
    for suffix, repl in (("ies", "y"), ("ing", ""), ("es", ""), ("ed", ""), ("s", "")):
        if w.endswith(suffix) and len(w) - len(suffix) >= 3:
            base = w[: -len(suffix)] + repl
            if base in _READ_STEMS or base in _WRITE_STEMS:
                return base
            if suffix in ("ing", "ed", "es") and (base + "e") in _READ_STEMS | set(_WRITE_STEMS):
                return base + "e"
    return w


def _camel_split(text: str) -> str:
    return re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text))


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[_\W]+", _camel_split(text).lower()) if t]


_SGD = re.compile(r"^([A-Za-z]+)_(\d+)_([A-Za-z]+)$")


def capability_of(tool: str) -> str:
    """``Buses_3_FindBus`` → ``buses``; ``game_rewards.get`` → ``game rewards``."""
    m = _SGD.match(tool)
    if m:
        return m.group(1).lower()
    if "." in tool:
        head = tool.rsplit(".", 1)[0]
        return " ".join(t for t in _tokens(head) if not t.isdigit() and t != "api") or "general"
    head = re.split(r"[._]", tool)[0]
    return re.sub(r"\d+$", "", head).lower() or "general"


def _name_parts(tool: str) -> tuple[list[str], list[str]]:
    """(verb-bearing tokens, class tokens) of a tool name."""
    m = _SGD.match(tool)
    if m:
        return _tokens(m.group(3)), []
    if "." in tool:
        head, method = tool.rsplit(".", 1)
        cls = [t for t in _tokens(head) if not t.isdigit() and t != "api"]
        return _tokens(method), cls
    return _tokens(tool), []


def _description_verb(description: str) -> str | None:
    """The leading verb of the declared description, as a stem, if known."""
    for raw in re.findall(r"[A-Za-z]+", description)[:3]:
        stem = _stem(raw)
        if stem in _READ_STEMS or stem in _WRITE_STEMS:
            return stem
        if raw.lower() not in {"this", "the", "a", "an", "function", "tool", "api",
                               "endpoint", "method", "it", "to", "used"}:
            return None
    return None


def _description_object(description: str) -> list[str]:
    """Content tokens of the description's first noun phrase after its verb."""
    first = re.split(r"(?<=[.;:!?])\s", description.strip(), maxsplit=1)[0]
    words = re.findall(r"[A-Za-z][A-Za-z\-]*", first)
    out: list[str] = []
    started = False
    for raw in words:
        w = raw.lower()
        if not started:
            if _stem(w) in _READ_STEMS or _stem(w) in _WRITE_STEMS:
                started = True
            continue
        if w in {"of", "for", "to", "in", "on", "at", "by", "with", "from", "and",
                 "or", "that", "which", "based", "using", "via", "into", "about"}:
            if out:
                break
            continue
        if w in _STOP or _stem(w) in _READ_STEMS or _stem(w) in _WRITE_STEMS:
            continue
        out.append(w)
        if len(out) == 3:
            break
    return out


#: Development switch: content words of the description's first sentence
#: become aliases. The per-episode lexicon drops any word two tools share.
DESCRIPTION_CONTENT_ALIASES = True


def _description_content(description: str) -> list[str]:
    first = re.split(r"(?<=[.;!?])\s", description.strip(), maxsplit=1)[0]
    out = []
    for raw in re.findall(r"[A-Za-z][A-Za-z\-]+", first):
        w = raw.lower()
        if len(w) <= 3 or w in _STOP or w in _DESCRIPTION_FILLER:
            continue
        if _stem(w) in _READ_STEMS or _stem(w) in _WRITE_STEMS:
            continue
        out.append(w)
    return out


_DESCRIPTION_FILLER = frozenset({
    "function", "tool", "endpoint", "method", "request", "response", "returns",
    "result", "results", "parameter", "parameters", "specified", "provided",
    "given", "including", "include", "includes", "such", "like", "also",
    "within", "between", "other", "more", "than", "only", "optional",
    "optionally", "will", "should", "must", "would", "could", "this", "that",
    "them", "they", "there", "here", "then", "into", "onto", "upon", "over",
    "under", "under", "after", "before", "while", "during", "against",
    "along", "across", "based", "according", "various", "multiple", "single",
    "default", "otherwise", "whether", "either", "whose", "allows", "allow",
    "enables", "used", "uses", "user", "users", "system", "service",
    "services", "application", "app", "client", "server", "account",
})


def _number_variant(phrase: str) -> str:
    head, _, tail = phrase.rpartition(" ")
    if tail.endswith("s") and len(tail) > 3:
        return (head + " " + tail[:-1]).strip()
    return (head + " " + tail + "s").strip()


def author_contract(tool: str, description: str = "") -> ToolContract:
    """Deterministic contract from tool metadata: name and declared description."""
    verb_toks, class_toks = _name_parts(tool)
    name_verb = next(
        (t for t in verb_toks if _stem(t) in _READ_STEMS or _stem(t) in _WRITE_STEMS), None
    )
    name_stem = _stem(name_verb) if name_verb else None
    desc_stem = _description_verb(description) if description else None

    stems = [s for s in (name_stem, desc_stem) if s]
    writes = [s for s in stems if s in _WRITE_STEMS]
    if writes:
        # The writing reading wins any disagreement: never bless a write as a read.
        effect, mutation = _WRITE_STEMS[writes[0]], True
    elif stems:
        effect, mutation = "read", False
    else:
        effect, mutation = "update", True

    resource_toks = [
        t for t in verb_toks
        if t != name_verb and not t.isdigit() and t not in _STOP
    ] or [t for t in class_toks if t not in _STOP]
    resource = " ".join(resource_toks) or capability_of(tool)

    aliases: list[str] = []
    for i in range(len(resource_toks)):
        for j in range(i + 1, len(resource_toks) + 1):
            aliases.append(" ".join(resource_toks[i:j]))
    if class_toks:
        aliases.append(" ".join(class_toks))
        aliases.extend(t for t in class_toks if t not in _STOP)
    obj = _description_object(description) if description else []
    if obj:
        aliases.append(" ".join(obj))
        aliases.append(obj[-1])
    if DESCRIPTION_CONTENT_ALIASES and description:
        aliases.extend(_description_content(description))
    aliases.extend([_number_variant(a) for a in list(aliases)])
    aliases = [a for a in dict.fromkeys(aliases) if a and a != resource and len(a) > 2]
    return ToolContract(
        tool=tool, capability=capability_of(tool), effect=effect,
        resource_type=resource, mutation=mutation, argument_roles={},
        resource_aliases=tuple(aliases),
    )


def author_bundle(
    tools: list[str], descriptions: Mapping[str, str] | None = None
) -> ToolContractRegistry:
    descriptions = descriptions or {}
    return ToolContractRegistry(
        contracts=[author_contract(t, descriptions.get(t, "")) for t in sorted(set(tools))]
    )


_ALL_EFFECT_WORDS = frozenset(
    {kw for kws in EFFECT_VOCABULARY.values() for kw in kws}
    | _READ_STEMS | set(_WRITE_STEMS)
)


def _lexicon_word_ok(phrase: str) -> bool:
    words = phrase.split()
    if not words or len(phrase) <= 2:
        return False
    if all(w in _STOP or w in _ALL_EFFECT_WORDS or w.isdigit() for w in words):
        return False
    return not (len(words) == 1 and (words[0] in _STOP or words[0] in _ALL_EFFECT_WORDS))


def resource_lexicon(bundle: ToolContractRegistry, tools: list[str]) -> dict[str, str]:
    """Discriminative resource vocabulary for the tools in scope.

    Derived from the CONTRACTS, never from tasks. Maps each phrase to the one
    tool it names. A phrase that names more than one tool in scope ("movie"
    for both ``FindMovies`` and ``BuyMovieTickets``) cannot say which tool the
    task is about, so it is left out: it may neither support nor refute.
    Call it with the tools an agent can actually call in the episode.
    """
    primary: dict[str, set[str]] = {}
    derived: dict[str, set[str]] = {}
    for tool in tools:
        contract = bundle.get(tool)
        if contract is None:
            continue
        own = {contract.resource_type, _number_variant(contract.resource_type)}
        for phrase in (contract.resource_type, *contract.resource_aliases):
            if _lexicon_word_ok(phrase):
                table = primary if phrase in own else derived
                table.setdefault(phrase, set()).add(tool)
    # A tool's own resource name outranks another tool's derived alias:
    # "trains" names Trains_1_FindTrains even though "trains" is also a
    # number variant of the "train" n-gram in "train tickets".
    lexicon: dict[str, str] = {}
    for phrase in primary.keys() | derived.keys():
        owners = primary.get(phrase) or derived.get(phrase, set())
        if len(owners) == 1:
            lexicon[phrase] = next(iter(owners))
    return lexicon


def full_resource_set(bundle: ToolContractRegistry, tools: list[str]) -> frozenset[str]:
    return frozenset(c.resource_type for c in (bundle.get(t) for t in tools) if c)


# --- Role B: intent extraction from the task text only ----------------------

_NEGATION = frozenset({"not", "no", "dont", "don't", "never", "without", "avoid",
                       "prevent", "stop", "cannot", "can't", "won't", "shouldn't"})
_WEAK_READ = frozenset({"need", "want", "provide", "tell", "give", "review",
                        "know", "access"})
_READ_FAMILY = frozenset({"read", "retrieve", "search", "list", "get", "query", "lookup"})
#: Mutation verbs outside EFFECT_VOCABULARY. Their presence means the task may
#: ask for a write that no grounded effect can express, so no read is claimed.
_UNGROUNDABLE_WRITES = frozenset({
    "buy", "purchase", "reserve", "rent", "order", "pay", "hire", "call",
    "play", "post", "upload", "invite", "launch", "install", "enable",
    "disable", "turn", "toggle", "rename", "replace", "run", "execute",
})


def _negated(lowered: str, start: int) -> bool:
    before = re.findall(r"[a-z']+", lowered[:start])[-3:]
    return any(w in _NEGATION for w in before)


_ACQUISITIVE_CUES = frozenset({"need", "want"})
_INDEFINITE = frozenset({"a", "an", "some", "one", "two", "three", "four", "five",
                         "another", "someone", "somebody", "something"})


def _acquisitive(lowered: str, hit: tuple[int, str]) -> bool:
    """``need``/``want`` followed by an indefinite object asks to obtain something."""
    if hit[1].lower() not in _ACQUISITIVE_CUES:
        return False
    after = re.findall(r"[a-z']+", lowered[hit[0] + len(hit[1]):])[:2]
    return bool(after) and after[0] in _INDEFINITE


def _inside_longer(tok: str, chosen: str, lowered: str) -> bool:
    """Is every occurrence of *tok* part of an occurrence of *chosen*?

    "tickets" inside "movie tickets" is the same mention, not a second
    resource.
    """
    if tok == chosen or tok not in chosen:
        return False
    spans = [(m.start(), m.end()) for m in re.finditer(re.escape(chosen), lowered)]
    for m in re.finditer(r"\b" + re.escape(tok) + r"\b", lowered):
        if not any(s <= m.start() and m.end() <= e for s, e in spans):
            return False
    return True


def _has_ungroundable_write(lowered: str) -> bool:
    for word in _UNGROUNDABLE_WRITES:
        found = re.search(r"\b" + re.escape(word) + r"\b", lowered)
        if found is not None and not _negated(lowered, found.start()):
            return True
    return False


def extract_intent(task: str, lexicon: Mapping[str, str] | set[str],
                   full_resources: frozenset[str] = frozenset()) -> TaskIntent | None:
    """Deterministic extractor: user task text ONLY. ``None`` when not grounded."""
    if not task:
        return None
    lowered = task.lower()

    hits: dict[str, tuple[int, str]] = {}
    strong_read: tuple[int, str] | None = None
    weak_read: tuple[int, str] | None = None
    for eff, keywords in EFFECT_VOCABULARY.items():
        family = "read" if eff in _READ_FAMILY else eff
        for kw in keywords:
            for m in re.finditer(rf"\b{re.escape(kw)}\b", lowered):
                if _negated(lowered, m.start()):
                    continue
                hit = (m.start(), task[m.start():m.end()])
                if family == "read":
                    if kw in _WEAK_READ:
                        if weak_read is None or hit[0] < weak_read[0]:
                            weak_read = hit
                    elif strong_read is None or hit[0] < strong_read[0]:
                        strong_read = hit
                elif family not in hits or hit[0] < hits[family][0]:
                    hits[family] = hit
                break
    if len(hits) > 1:
        return None
    if weak_read is not None and strong_read is None and _acquisitive(lowered, weak_read):
        # "I need a ride", "I want a therapist": a request to obtain something,
        # not to be told something. It establishes no read.
        weak_read = None
    read_hit = strong_read or weak_read
    effect: str
    span: str
    if hits:
        ((write_family, (write_pos, write_span)),) = hits.items()
        if strong_read is not None and strong_read[0] < write_pos:
            # The user's leading verb states the request; a later mutation
            # keyword is usually a parameter ("... page size set to 50").
            effect, span = "read", strong_read[1]
        else:
            # A mutation keyword beats weak read cues and wins ties.
            effect, span = write_family, write_span
    elif read_hit is None:
        return None
    elif _has_ungroundable_write(lowered):
        # "buy tickets": a write no grounded effect can express.
        return None
    else:
        effect, span = "read", read_hit[1]

    action_pos = lowered.find(span.lower())

    def _rank(tok: str) -> tuple:
        return (tok in full_resources, len(tok.split()), len(tok),
                -abs(lowered.find(tok) - action_pos))

    matches = sorted(
        (tok for tok in lexicon if re.search(rf"\b{re.escape(tok)}\b", lowered)),
        key=_rank, reverse=True,
    )
    if not matches:
        return None
    resource = matches[0]
    if isinstance(lexicon, Mapping):
        named = {lexicon[resource]} | {
            lexicon[tok] for tok in matches
            if tok != resource and not _inside_longer(tok, resource, lowered)
        }
        if len(named) > 1:
            # The task names resources of two different tools in scope
            # ("see the movie ... get three tickets"). Picking one would be a
            # guess, and a wrong guess either refutes the right tool or
            # supports the wrong one. No intent; downstream stays UNKNOWN.
            return None
    r_idx = lowered.find(resource)
    r_span = task[r_idx:r_idx + len(resource)]
    return TaskIntent(
        operation=effect, resource_type=resource, requested_effect=effect,
        source_spans=(r_span,), action_spans=(span,), resource_spans=(r_span,),
        proposed_by=BUNDLE_VERSION,
    )
