"""Saída de terminal: cores, tabelas e mensagens padronizadas.

Nenhuma dependência externa. As cores usam sequências ANSI e são desligadas
automaticamente quando a saída não é um terminal (redirecionamento para
arquivo, pipe para outro comando) ou quando NO_COLOR está definido, seguindo
a convenção de https://no-color.org.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Sequence

_RESET = "\033[0m"
_CORES = {
    "vermelho": "\033[31m",
    "verde": "\033[32m",
    "amarelo": "\033[33m",
    "azul": "\033[34m",
    "ciano": "\033[36m",
    "cinza": "\033[90m",
    "negrito": "\033[1m",
}


def _cores_disponiveis() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        return _habilitar_ansi_windows()
    return True


def _habilitar_ansi_windows() -> bool:
    import ctypes

    ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(-11)
    modo = ctypes.c_uint32()
    if not kernel32.GetConsoleMode(handle, ctypes.byref(modo)):
        return False
    return bool(kernel32.SetConsoleMode(handle, modo.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))


_USAR_COR = _cores_disponiveis()


def colorir(texto: str, cor: str) -> str:
    if not _USAR_COR or cor not in _CORES:
        return texto
    return f"{_CORES[cor]}{texto}{_RESET}"


def info(mensagem: str) -> None:
    print(mensagem)


def sucesso(mensagem: str) -> None:
    print(colorir(mensagem, "verde"))


def aviso(mensagem: str) -> None:
    print(colorir(f"aviso: {mensagem}", "amarelo"), file=sys.stderr)


def erro(mensagem: str) -> None:
    print(colorir(f"erro: {mensagem}", "vermelho"), file=sys.stderr)


def secao(titulo: str) -> None:
    print()
    print(colorir(titulo, "negrito"))
    print(colorir("-" * len(titulo), "cinza"))


def campo(rotulo: str, valor: str, largura: int = 16) -> None:
    print(f"{colorir(rotulo.ljust(largura), 'cinza')} {valor}")


def tabela(cabecalhos: Sequence[str], linhas: Iterable[Sequence[str]]) -> None:
    dados = [[str(c) for c in linha] for linha in linhas]
    if not dados:
        print(colorir("(nenhum resultado)", "cinza"))
        return

    larguras = [len(c) for c in cabecalhos]
    for linha in dados:
        for i, celula in enumerate(linha):
            larguras[i] = max(larguras[i], len(celula))

    print(colorir("  ".join(c.ljust(larguras[i]) for i, c in enumerate(cabecalhos)), "negrito"))
    print(colorir("  ".join("-" * largura for largura in larguras), "cinza"))
    for linha in dados:
        print("  ".join(celula.ljust(larguras[i]) for i, celula in enumerate(linha)))


def arvore(rotulo: str, filhos: Iterable[tuple[str, Iterable]], prefixo: str = "") -> None:
    """Desenha uma árvore a partir de pares (rótulo, filhos)."""
    if not prefixo:
        print(rotulo)
    itens = list(filhos)
    for indice, (nome, netos) in enumerate(itens):
        ultimo = indice == len(itens) - 1
        print(f"{prefixo}{'└─ ' if ultimo else '├─ '}{nome}")
        arvore(nome, netos, prefixo + ("   " if ultimo else "│  "))
