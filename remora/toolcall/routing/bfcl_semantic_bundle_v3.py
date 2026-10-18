# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Deterministic semantic bundle v3: intent extraction that keeps qualifiers.

v2 (``bfcl_semantic_bundle_v2.py``) is frozen: the sealed C-ext4 manifest pins
its hash together with ``goal_match.py`` and ``bfcl_arms.py``. An external
audit (RMR-AUD-009, 2026-10-18) showed that v2 still grounds a mutation in
three kinds of sentence that do not ask for one:

* **A conditional clause.** "Inspect booking B-104 before cancel." v2 checks
  the three words before an effect keyword for a negation only, and hands
  goal matching the bare keyword, so the "before" never reaches
  ``goal_match``'s own conditional check.
* **A question about the action.** "Tell me if I can cancel booking B-104."
  asks for information. v2 lets any mutation keyword beat the weak read cue
  "tell", wherever it stands.
* **A conditional with a subject.** "Review the policy before we cancel
  booking B-104." The word before "cancel" is "we", so even a span with
  context would pass ``goal_match``'s one-word check.

v3 changes Role B (intent extraction) only. Role A (contract authoring) is
v2's, unchanged and re-exported, so the contracts v3 is judged against are the
contracts v2 was judged against. The rules added:

* A mutation keyword is *qualified*, and grounds nothing, when its clause
  places a conditional word ("before", "if", "whether", "until", ...) within
  the four words before it, or frames it as a question about the action
  ("tell me if", "can I", "is it possible to", ...). The clause runs back to
  the nearest punctuation mark, so "If possible, cancel booking B-104"
  remains a cancel request.
* Action spans carry the keyword with up to three preceding words of its
  clause, quoted verbatim, so ``goal_match`` sees the same context the
  extractor judged.
* "inspect", "examine" and "investigate" are read cues for extraction. The
  frozen ``EFFECT_VOCABULARY`` does not contain them, so an intent whose only
  read verb is one of these cannot be grounded; v3 then returns no intent
  rather than one ``goal_match`` would reject on a technicality.

v3 is a development artifact. It has not been run on any sealed set, it is
wired into no runner or claim, and numbers from the spent development sets
(``scripts/bfcl_v3_extractor_dev_compare.py``) may not be cited as results.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from remora.toolcall.routing.bfcl_semantic_bundle_v2 import (
    _READ_FAMILY,
    _WEAK_READ,
    USES_DESCRIPTIONS,
    _acquisitive,
    _has_ungroundable_write,
    _inside_longer,
    _negated,
    author_bundle,
    author_contract,
    capability_of,
    full_resource_set,
    resource_lexicon,
)
from remora.toolcall.routing.goal_match import EFFECT_VOCABULARY, TaskIntent

__all__ = [
    "BUNDLE_VERSION", "PER_EPISODE_LEXICON", "USES_DESCRIPTIONS",
    "author_bundle", "author_contract", "capability_of", "extract_intent",
    "full_resource_set", "resource_lexicon",
]

BUNDLE_VERSION = "bfcl_semantic_bundle_v3"
#: The lexicon is built per episode from the tools in scope, as in v2.
PER_EPISODE_LEXICON = True

#: Words that make a following mutation conditional rather than requested.
#: ``goal_match._CONDITIONAL_WORDS`` plus "whether".
_CONDITIONAL = frozenset({
    "before", "after", "when", "once", "if", "until", "unless", "following",
    "prior", "whether",
})
#: How many words before a mutation keyword a conditional word may stand.
_CONDITIONAL_REACH = 4
#: Frames that turn a following mutation into a question about it.
_INTERROGATIVE = re.compile(
    r"\b(?:"
    r"(?:tell|let)\s+(?:me|us)\s+(?:know\s+)?(?:if|whether)"
    r"|(?:can|could|may|might|should|must|do)\s+(?:i|we)"
    r"|(?:am\s+i|are\s+we)\s+(?:able|allowed|permitted)"
    r"|is\s+it\s+(?:possible|allowed|ok|okay)"
    r"|how\s+(?:do|can|would|should)\s+(?:i|we)"
    r"|what\s+happens\s+if"
    r"|find\s+out\s+(?:if|whether)"
    r")\b"
)
#: Read cues for extraction that the frozen EFFECT_VOCABULARY cannot ground.
_UNGROUNDABLE_READ = frozenset({"inspect", "examine", "investigate"})
#: Words of preceding context quoted into an action span.
_SPAN_CONTEXT = 3

_CLAUSE_BREAK = re.compile(r"[.;:!?,()\[\]\n]")
_WORD = re.compile(r"[a-z']+")


def _clause_start(lowered: str, start: int) -> int:
    """Index where the clause containing position *start* begins."""
    breaks = [m.end() for m in _CLAUSE_BREAK.finditer(lowered, 0, start)]
    return breaks[-1] if breaks else 0


def _qualified(lowered: str, start: int) -> bool:
    """Is the keyword at *start* conditional or asked about, not requested?"""
    clause = lowered[_clause_start(lowered, start):start]
    if any(w in _CONDITIONAL for w in _WORD.findall(clause)[-_CONDITIONAL_REACH:]):
        return True
    return _INTERROGATIVE.search(clause) is not None


def _context_span(task: str, lowered: str, start: int, end: int) -> str:
    """The keyword with up to three preceding words of its clause, verbatim.

    A keyword glued to the text before it ("<<question>>Find") keeps the bare
    keyword: goal matching splits on whitespace and would see one word.
    """
    if start > 0 and not lowered[start - 1].isspace():
        return task[start:end]
    clause_from = _clause_start(lowered, start)
    words = list(re.finditer(r"\S+", lowered[clause_from:start]))
    begin = clause_from + words[-_SPAN_CONTEXT].start() if len(words) >= _SPAN_CONTEXT else (
        clause_from + words[0].start() if words else start)
    return task[begin:end].strip()


def extract_intent(task: str, lexicon: Mapping[str, str] | set[str],
                   full_resources: frozenset[str] = frozenset()) -> TaskIntent | None:
    """Deterministic extractor: user task text ONLY. ``None`` when not grounded.

    v2's algorithm with qualified mutations removed, interrogative frames read
    as requests for information, and context kept in the action span.
    """
    if not task:
        return None
    lowered = task.lower()

    hits: dict[str, tuple[int, int]] = {}
    strong_read: tuple[int, int] | None = None
    weak_read: tuple[int, int] | None = None
    qualified_mutation = False
    vocabulary = dict(EFFECT_VOCABULARY)
    vocabulary["read"] = EFFECT_VOCABULARY["read"] | _UNGROUNDABLE_READ
    for eff, keywords in vocabulary.items():
        family = "read" if eff in _READ_FAMILY else eff
        for kw in keywords:
            for m in re.finditer(rf"\b{re.escape(kw)}\b", lowered):
                if _negated(lowered, m.start()):
                    continue
                if family != "read" and _qualified(lowered, m.start()):
                    qualified_mutation = True
                    continue
                hit = (m.start(), m.end())
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
    if weak_read is not None and strong_read is None and _acquisitive(
            lowered, (weak_read[0], task[weak_read[0]:weak_read[1]])):
        weak_read = None
    read_hit = strong_read or weak_read
    if hits:
        ((write_family, write_hit),) = hits.items()
        if strong_read is not None and strong_read[0] < write_hit[0]:
            effect, hit = "read", strong_read
        else:
            effect, hit = write_family, write_hit
    elif read_hit is None:
        return None
    elif _has_ungroundable_write(lowered) and not qualified_mutation:
        return None
    else:
        effect, hit = "read", read_hit

    if effect == "read" and lowered[hit[0]:hit[1]] in _UNGROUNDABLE_READ:
        # The read cue exists for extraction only; goal matching under the
        # frozen vocabulary cannot ground it.
        return None
    span = _context_span(task, lowered, hit[0], hit[1])
    action_pos = hit[0]

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
            return None
    r_idx = lowered.find(resource)
    r_span = task[r_idx:r_idx + len(resource)]
    return TaskIntent(
        operation=effect, resource_type=resource, requested_effect=effect,
        source_spans=(r_span,), action_spans=(span,), resource_spans=(r_span,),
        proposed_by=BUNDLE_VERSION,
    )
