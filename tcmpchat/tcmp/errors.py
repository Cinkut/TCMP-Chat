"""Wyjątki protokołu TCMP."""

from .constants import ERR_NAMES, FATAL_ERRORS


class TCMPError(Exception):
    """Błąd protokołu TCMP niosący numeryczny kod błędu.

    Warstwa serwera łapie ten wyjątek, buduje ramkę ERR z polem
    error_code, a gdy ``fatal == True`` - zamyka połączenie
    (BYE reason=0x02). Pozwala to przenieść reguły walidacji ze
    specyfikacji (Etap1 §3.4) z warstwy parsera do warstwy sesji
    bez powielania mapowania kod->zachowanie.
    """

    def __init__(self, error_code: int, message: str = ""):
        self.error_code = error_code
        self.fatal = error_code in FATAL_ERRORS
        name = ERR_NAMES.get(error_code, f"0x{error_code:04X}")
        super().__init__(f"{name}: {message}" if message else name)
