"""Audited asset importance (CTEM-GAP-02): vocabulary and pure rules.

Asset importance is the consequence of losing or degrading one asset in this
environment. It is an operator assertion, recorded with an actor label, a
reason, and an append-only history. It is deliberately separate from:

- finding severity (the technical impact of a weakness);
- the Operational Attention Score (a ranking signal);
- the decision action band (which may read importance as one input);
- finding work tracking (what people are doing about a finding).

Nothing here infers importance. Asset names, hostnames, software titles,
classifications, and AI output never set or suggest a value. When no operator
has assigned a value, importance is ``unknown``, and unknown is never treated
as low.

This module has no database, clock, network, or model dependency.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal


ImportanceValue = Literal["critical", "high", "standard", "low"]
EffectiveImportance = Literal["critical", "high", "standard", "low", "unknown"]
ImportanceSource = Literal["operator-assigned", "unassigned"]
ImportanceEventType = Literal["assigned", "changed", "reviewed", "withdrawn"]
ImportanceDirection = Literal["initial", "raised", "lowered", "unchanged", "withdrawn", "reassigned"]
ReviewState = Literal["current", "review-due", "not-applicable"]

# Ascending order of consequence. `unknown` is intentionally not ranked: it is
# the absence of an assertion, not a low value.
ASSIGNABLE_IMPORTANCE: tuple[ImportanceValue, ...] = ("low", "standard", "high", "critical")
EFFECTIVE_IMPORTANCE: tuple[EffectiveImportance, ...] = (*ASSIGNABLE_IMPORTANCE, "unknown")
IMPORTANCE_PRINCIPAL = "api-admin-token"

# An assignment is a human assertion that can drift from reality. After this
# interval the read API reports it as due for review. Review age is shown to
# people only; it is not a decision input in `oaw.decision.rules.v2`.
IMPORTANCE_REVIEW_INTERVAL = timedelta(days=180)


class ImportanceRuleError(ValueError):
    """A requested importance change that the rules do not allow."""


def _rank(value: str) -> int:
    return ASSIGNABLE_IMPORTANCE.index(value)  # type: ignore[arg-type]


def validate_assignable(value: str) -> ImportanceValue:
    if value not in ASSIGNABLE_IMPORTANCE:
        raise ImportanceRuleError("importance must be critical, high, standard, or low")
    return value  # type: ignore[return-value]


def assignment_event_type(previous: str | None, new: str) -> ImportanceEventType:
    """Classify an assignment of ``new`` over the current stored value.

    ``previous`` is ``None`` when the asset has never had an assignment and
    ``"unknown"`` after a withdrawal.
    """

    validate_assignable(new)
    if previous is None or previous == "unknown":
        return "assigned"
    if previous not in ASSIGNABLE_IMPORTANCE:
        raise ImportanceRuleError("stored importance is not a reviewed value")
    if previous == new:
        return "reviewed"
    return "changed"


def direction(previous: str | None, new: str) -> ImportanceDirection:
    """How a recorded event moved importance. Derived, never stored."""

    if new == "unknown":
        return "withdrawn"
    if previous is None:
        return "initial"
    if previous == "unknown":
        return "reassigned"
    if previous == new:
        return "unchanged"
    return "raised" if _rank(new) > _rank(previous) else "lowered"


def effective_source(importance: str) -> ImportanceSource:
    return "operator-assigned" if importance in ASSIGNABLE_IMPORTANCE else "unassigned"


def review_state(importance: str, reviewed_at: datetime | None, now: datetime) -> ReviewState:
    if importance not in ASSIGNABLE_IMPORTANCE or reviewed_at is None:
        return "not-applicable"
    if now.tzinfo is None or reviewed_at.tzinfo is None:
        raise ValueError("importance review timestamps must include a timezone")
    age = now.astimezone(timezone.utc) - reviewed_at.astimezone(timezone.utc)
    return "review-due" if age >= IMPORTANCE_REVIEW_INTERVAL else "current"


__all__ = [
    "ASSIGNABLE_IMPORTANCE",
    "EFFECTIVE_IMPORTANCE",
    "IMPORTANCE_PRINCIPAL",
    "IMPORTANCE_REVIEW_INTERVAL",
    "ImportanceRuleError",
    "assignment_event_type",
    "direction",
    "effective_source",
    "review_state",
    "validate_assignable",
]
