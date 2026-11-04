"""Removal requests: drafted under the law that applies to the subject, approved by the
operator, then sent by email, prefilled into a web form, prepared for California DROP,
or rendered as a letter. Replies are read from a dedicated mailbox; verification links
are followed only when they point at the broker's own hosts."""

from unlist.requests.engine import (
    OPEN_STATES,
    STATES,
    approve,
    draft_blind,
    draft_for_confirmed,
    draft_request,
    send_approved,
    set_state,
)

__all__ = [
    "OPEN_STATES",
    "STATES",
    "approve",
    "draft_blind",
    "draft_for_confirmed",
    "draft_request",
    "send_approved",
    "set_state",
]
