"""Trava consultiva de cofre.

Dois processos gravando o mesmo .arca em sequência não corrompem o arquivo --
a gravação é atômica --, mas o segundo sobrescreve silenciosamente o trabalho
do primeiro, porque cada um tem a sua cópia em memória. A trava existe para
transformar essa perda silenciosa em um aviso.

É uma trava consultiva: um arquivo irmão, com sufixo .lock, contendo quem
abriu, em qual máquina e quando. Nada impede que outro programa ignore o
arquivo. Também é possível que a trava fique órfã, se o processo morrer sem
liberá-la, e por isso a informação registrada permite ao usuário decidir com
conhecimento de causa, além de o próprio Arca detectar sozinho as travas
deixadas por processos que já não existem nesta máquina.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from arca.core.errors import VaultBusyError

SUFIXO_TRAVA = ".lock"


@dataclass(frozen=True, slots=True)
class LockInfo:
    pid: int
    host: str
    user: str
    since: str

    def describe(self) -> str:
        return f"{self.user}@{self.host} (processo {self.pid}), desde {self.since}"


class VaultLock:
    """Trava consultiva sobre um arquivo de cofre."""

    def __init__(self, cofre: Path) -> None:
        self.vault_path = cofre
        self.lock_path = cofre.with_suffix(cofre.suffix + SUFIXO_TRAVA)
        self._nossa = False

    def acquire(self, forcar: bool = False) -> None:
        existente = self.read()
        # Uma trava órfã, de processo local que já terminou, pode ser tomada.
        if existente is not None and not forcar and _processo_local_vivo(existente):
            raise VaultBusyError(
                f"o cofre está aberto por {existente.describe()}. "
                "Feche a outra janela ou abra somente leitura."
            )
        self._escrever()
        self._nossa = True

    def release(self) -> None:
        if not self._nossa:
            return
        self.lock_path.unlink(missing_ok=True)
        self._nossa = False

    def read(self) -> LockInfo | None:
        try:
            bruto = json.loads(self.lock_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        try:
            return LockInfo(
                pid=int(bruto["pid"]),
                host=str(bruto["host"]),
                user=str(bruto["user"]),
                since=str(bruto["since"]),
            )
        except (KeyError, TypeError, ValueError):
            return None

    @property
    def held_by_us(self) -> bool:
        return self._nossa

    def _escrever(self) -> None:
        conteudo = {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "user": _usuario(),
            "since": datetime.now(UTC).replace(microsecond=0).isoformat(),
        }
        self.lock_path.write_text(json.dumps(conteudo, ensure_ascii=False), encoding="utf-8")

    def __enter__(self) -> VaultLock:
        self.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


def _processo_local_vivo(info: LockInfo) -> bool:
    """Só sabemos responder para travas criadas nesta mesma máquina."""
    if info.host != socket.gethostname():
        return True
    if info.pid == os.getpid():
        return True
    return _processo_existe(info.pid)


def _processo_existe(pid: int) -> bool:
    """Na dúvida, responde que existe: perder trabalho é pior que um falso alarme."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        return _processo_existe_windows(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # existe, mas pertence a outro usuário
    except OSError:
        return True
    return True


def _processo_existe_windows(pid: int) -> bool:
    # os.kill no Windows encerra o processo mesmo com sinal 0, então a
    # verificação precisa passar direto pela API do sistema.
    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    ERROR_ACCESS_DENIED = 5
    STILL_ACTIVE = 259

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ctypes.get_last_error() == ERROR_ACCESS_DENIED
    try:
        codigo = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(codigo)):
            return True
        return codigo.value == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def _usuario() -> str:
    for variavel in ("USERNAME", "USER", "LOGNAME"):
        valor = os.environ.get(variavel)
        if valor:
            return valor
    return "desconhecido"
