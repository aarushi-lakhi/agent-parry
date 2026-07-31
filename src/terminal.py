"""Terminal escape sequences: one definition of what they are, and how to remove them.

Text that reaches a terminal or a transcript is interpreted, not just displayed.
An escape sequence in a tool argument or a tool result can clear the scrollback,
forge a line that reads like the proxy's own output, rewrite the window title, or
render the dangerous half of a command invisible with the conceal attribute. None
of that is a prompt injection: the model is not being persuaded of anything, the
human reading the transcript is being shown something that did not happen.

Both directions are covered from here. :data:`DANGEROUS_ESCAPE_RE` is the subset
worth refusing a call over, :data:`SGR_STYLE_RE` is the colour-and-style subset
that is merely anomalous in an argument, and :func:`strip_terminal_escapes`
removes every sequence of either kind from text on its way back to the client.

Not covered: a bare carriage return, which overwrites the line just printed and
so is a forgery primitive of its own. ``\\r`` is ordinary in CRLF text and
stripping it would corrupt every Windows file a tool reads, so it stays.
"""

from __future__ import annotations

import re

CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
"""Every C0 control character plus DEL, the class a Markdown cell has to lose.

Shared with ``src.scanner._md_cell`` so "control character" has one spelling in
the codebase. Broader than :data:`RESIDUAL_CONTROL_RE`, because a table cell
cannot survive a newline either.
"""

RESIDUAL_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]")
"""Control characters that are never content, once escape sequences are gone.

Tab, newline and carriage return are absent on purpose: they are text. A lone
ESC, a BEL and the 8-bit C1 range are what is left of a malformed or truncated
sequence, and leaving those in place lets a terminal resynchronise on the next
byte and interpret it as a command.
"""

CSI_RE = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]")
"""One CSI sequence, 7-bit or 8-bit introducer, in the shape ECMA-48 defines."""

OSC_RE = re.compile(r"(?:\x1b\]|\x9d)[^\x07\x1b\x9c\n]*(?:\x07|\x1b\\|\x9c)?")
"""One OSC sequence. The terminator is optional so a truncated one still matches.

An unterminated OSC is not a broken payload, it is the interesting case: a
terminal swallows everything after it while waiting for a string terminator that
never comes, which hides the rest of the output. The body stops at a newline
anyway, because removing text a terminal would have hidden is safe while removing
text it would have shown is a second kind of corruption.
"""

DCS_RE = re.compile(r"(?:\x1bP|\x90)[^\x1b\x9c\n]*(?:\x1b\\|\x9c)?")
"""One DCS sequence, terminator optional for the same reason as OSC."""

_TWO_CHAR_RE = r"\x1b[ -/][0-~]|\x1b[ -~]"
"""nF sequences such as a charset designator, then any other two-character form."""

_TWO_CHAR_COMPLETE_RE = r"\x1b[ -/][0-~]|\x1b[ -OQ-Z\\^-~]"
"""The same, minus the ``[``, ``]`` and ``P`` introducers of the longer forms.

:data:`TERMINAL_ESCAPE_RE` wants those, so a truncated ``ESC [`` is removed whole
rather than leaving a bracket behind. A classifier must not, or every colour
sequence falls through to the two-character branch and reads as dangerous.
"""

TERMINAL_ESCAPE_RE = re.compile(
    rf"{OSC_RE.pattern}|{DCS_RE.pattern}|{CSI_RE.pattern}|{_TWO_CHAR_RE}"
)
"""Any escape sequence at all. OSC, DCS and CSI lead, because ``]``, ``P`` and
``[`` are also final bytes of the two-character forms and the longer match has to
win.
"""

DANGEROUS_ESCAPE_RE = re.compile(
    rf"{OSC_RE.pattern}"
    rf"|{DCS_RE.pattern}"
    r"|(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-ln-~]"
    r"|(?:\x1b\[|\x9b)(?:[0-9]{1,3};)*(?:8|28)m"
    rf"|{_TWO_CHAR_COMPLETE_RE}"
)
"""Every sequence except a plain colour or style change: erase, move, hide, relabel.

Written as "any CSI whose final byte is not ``m``, plus the conceal parameters of
the ones that are". Erase and cursor positioning wipe the scrollback and
reposition the write head, which is how a forged line gets printed over a real
one; private-mode switches reach the alternate screen; SGR 8 conceals and 28
reveals; OSC relabels the window and DCS carries device payloads; and a
two-character ``ESC c`` resets the terminal outright.

The conceal branch reads an extended colour spec ending in ``;8m``, such as
``38;5;8``, as a conceal. Telling them apart needs parameter counting rather than
a regex, and flagging is the fail-safe direction for a value that had no business
carrying an escape sequence at all.
"""

SGR_STYLE_RE = re.compile(r"(?:\x1b\[|\x9b)[0-9;]*m")
"""Colour and style sequences: anomalous in an argument, not worth a block."""


def find_terminal_escapes(text: str) -> list[re.Match[str]]:
    """Return every escape sequence in text, in order."""
    return list(TERMINAL_ESCAPE_RE.finditer(text))


def strip_terminal_escapes(text: str) -> tuple[str, int]:
    """Remove every escape sequence and residual control byte. Returns text and count.

    The count is of sequences and stray control bytes removed, so a caller can
    report that it acted without keeping the payload it just removed.

    Removal, not replacement with a marker: the surrounding text is real output a
    human is going to read, and splicing a marker into the middle of a log line
    is a second kind of corruption. What survives is what the text would have
    said to a terminal that had no escape handling at all.
    """
    stripped, escapes = TERMINAL_ESCAPE_RE.subn("", text)
    stripped, residual = RESIDUAL_CONTROL_RE.subn("", stripped)
    return stripped, escapes + residual


__all__ = [
    "CONTROL_CHARS_RE",
    "CSI_RE",
    "DANGEROUS_ESCAPE_RE",
    "DCS_RE",
    "OSC_RE",
    "RESIDUAL_CONTROL_RE",
    "SGR_STYLE_RE",
    "TERMINAL_ESCAPE_RE",
    "find_terminal_escapes",
    "strip_terminal_escapes",
]
