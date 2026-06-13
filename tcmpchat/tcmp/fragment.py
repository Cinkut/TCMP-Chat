import time
from dataclasses import dataclass, field
from .constants import MAX_TEXT_PER_FRAGMENT, TIMEOUT_FRAGMENT, ERR_INVALID_FRAG
from .errors import TCMPError

MAX_FRAGMENT_PAYLOAD: int = MAX_TEXT_PER_FRAGMENT  # 65 535


@dataclass
class Fragment:
    frag_num:  int
    more_data: bool
    data:      bytes


def fragment_payload(data: bytes, max_chunk: int = MAX_FRAGMENT_PAYLOAD) -> list[Fragment]:
    if not data:
        return [Fragment(frag_num=0, more_data=False, data=b'')]
    chunks = [data[i:i + max_chunk] for i in range(0, len(data), max_chunk)]
    last = len(chunks) - 1
    return [
        Fragment(frag_num=i, more_data=(i < last), data=chunk)
        for i, chunk in enumerate(chunks)
    ]


@dataclass
class _AssemblyState:
    chunks:        dict  = field(default_factory=dict)
    last_frag_num: int | None = None
    started_at:    float = field(default_factory=time.monotonic)


class ReassemblyBuffer:
    def __init__(self, timeout: float = TIMEOUT_FRAGMENT):
        self._timeout = timeout
        self._buffers: dict[int, _AssemblyState] = {}

    def receive(self, msg_id: int, frag_num: int, more_data: bool, data: bytes) -> bytes | None:
        self.check_timeouts()

        if msg_id not in self._buffers:
            if frag_num != 0:
                raise TCMPError(
                    ERR_INVALID_FRAG,
                    f"oczekiwano frag_num=0 dla nowej wiadomości, otrzymano {frag_num}",
                )
            self._buffers[msg_id] = _AssemblyState()

        state = self._buffers[msg_id]
        expected = len(state.chunks)
        if frag_num != expected:
            raise TCMPError(
                ERR_INVALID_FRAG, f"oczekiwano frag_num={expected}, otrzymano {frag_num}"
            )

        state.chunks[frag_num] = data
        if not more_data:
            state.last_frag_num = frag_num

        if state.last_frag_num is not None and len(state.chunks) == state.last_frag_num + 1:
            result = b''.join(state.chunks[i] for i in range(state.last_frag_num + 1))
            del self._buffers[msg_id]
            return result

        return None

    def check_timeouts(self) -> list[int]:
        now = time.monotonic()
        expired = [
            mid for mid, s in self._buffers.items()
            if now - s.started_at > self._timeout
        ]
        for mid in expired:
            del self._buffers[mid]
        return expired

    def discard(self, msg_id: int) -> None:
        self._buffers.pop(msg_id, None)
