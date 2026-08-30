"""Área de transferência para o modo terminal.

Cada sistema expõe um utilitário diferente e nenhum deles vem do Python, então
a implementação delega para o programa nativo. Sem dependências extras: o
custo é depender de `clip`, `pbcopy` ou `xclip`/`wl-copy` estarem presentes.

A senha vai para o processo auxiliar pela entrada padrão, e não como argumento
de linha de comando -- argumentos ficam visíveis na lista de processos para
qualquer usuário da máquina.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from contextlib import suppress

from arca.core.errors import ArcaError


def copiar(texto: str) -> None:
    comando = _comando()
    try:
        subprocess.run(comando, input=texto.encode("utf-8"), check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ArcaError(f"falha ao copiar para a área de transferência: {exc}") from exc


def limpar() -> None:
    with suppress(ArcaError):
        copiar("")


def disponivel() -> bool:
    try:
        _comando()
    except ArcaError:
        return False
    return True


def _comando() -> list[str]:
    if sys.platform == "win32":
        return ["clip"]
    if sys.platform == "darwin":
        return ["pbcopy"]
    for candidato, argumentos in (
        ("wl-copy", []),
        ("xclip", ["-selection", "clipboard"]),
        ("xsel", ["--clipboard", "--input"]),
    ):
        if shutil.which(candidato):
            return [candidato, *argumentos]
    raise ArcaError(
        "nenhum utilitário de área de transferência encontrado; "
        "instale wl-clipboard, xclip ou xsel"
    )
