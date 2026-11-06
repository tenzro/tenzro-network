"""Incremental Server-Sent Events decoder.

Network reads cut a stream at arbitrary byte offsets: inside a UTF-8
character, between the ``\\r`` and ``\\n`` of a line break, or in the middle of
a multi-line event. :class:`SseDecoder` buffers across reads and yields an
event only once its terminating blank line has arrived; :meth:`SseDecoder.finish`
flushes an event the stream ended without terminating.
"""

from __future__ import annotations

import codecs
from dataclasses import dataclass


@dataclass(frozen=True)
class SseEvent:
    """One dispatched event."""

    #: The ``data:`` lines, joined with ``\\n``.
    data: str
    #: The ``event:`` field, when the event named one.
    event: str | None = None
    #: The last ``id:`` seen on the stream so far.
    id: str | None = None


class SseDecoder:
    """Decodes a byte stream into :class:`SseEvent` s. Accepts ``\\r\\n``,
    ``\\n`` and ``\\r`` line breaks, skips ``:`` comment lines and ignores
    unknown fields."""

    def __init__(self) -> None:
        self._text = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._line: list[str] = []
        self._after_cr = False
        self._data: str | None = None
        self._event: str | None = None
        self._last_id: str | None = None

    def push(self, chunk: bytes) -> list[SseEvent]:
        """Absorb one network read and return the events it completed."""
        return self._consume(self._text.decode(chunk))

    def finish(self) -> list[SseEvent]:
        """End of stream: process an unterminated last line and dispatch its event."""
        out = self._consume(self._text.decode(b"", final=True))
        if self._line:
            self._end_line(out)
        self._dispatch(out)
        return out

    def _consume(self, s: str) -> list[SseEvent]:
        out: list[SseEvent] = []
        for ch in s:
            after_cr = self._after_cr
            self._after_cr = False
            if after_cr and ch == "\n":
                continue
            if ch == "\n":
                self._end_line(out)
            elif ch == "\r":
                self._end_line(out)
                self._after_cr = True
            else:
                self._line.append(ch)
        return out

    def _end_line(self, out: list[SseEvent]) -> None:
        line = "".join(self._line)
        self._line = []
        if not line:
            self._dispatch(out)
            return
        if line.startswith(":"):
            return
        field, colon, value = line.partition(":")
        if colon and value.startswith(" "):
            value = value[1:]
        if field == "data":
            self._data = value if self._data is None else f"{self._data}\n{value}"
        elif field == "event":
            self._event = value
        elif field == "id" and "\0" not in value:
            self._last_id = value

    def _dispatch(self, out: list[SseEvent]) -> None:
        event = self._event
        self._event = None
        if self._data is None:
            return
        out.append(SseEvent(data=self._data, event=event, id=self._last_id))
        self._data = None


__all__ = ["SseDecoder", "SseEvent"]
