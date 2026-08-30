"""Acesso às listas de palavras empacotadas com o Arca.

Duas listas, com finalidades opostas: uma alimenta o gerador de frases-senha,
a outra alimenta o estimador de força. Ambas são carregadas sob demanda e
mantidas em cache, porque nem toda execução precisa delas.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from pathlib import Path

ARQUIVO_PALAVRAS = "palavras-pt.txt"
ARQUIVO_SENHAS_COMUNS = "senhas-comuns.txt"


def _ler_recurso(nome: str) -> list[str]:
    texto = files("arca.resources").joinpath(nome).read_text(encoding="utf-8")
    return _linhas_uteis(texto)


def _linhas_uteis(texto: str) -> list[str]:
    linhas = (linha.strip() for linha in texto.splitlines())
    return [linha for linha in linhas if linha and not linha.startswith("#")]


@lru_cache(maxsize=1)
def wordlist() -> tuple[str, ...]:
    """Dicionário de frases-senha embutido (512 palavras, 9 bits cada)."""
    return tuple(_ler_recurso(ARQUIVO_PALAVRAS))


@lru_cache(maxsize=1)
def common_passwords() -> frozenset[str]:
    return frozenset(_ler_recurso(ARQUIVO_SENHAS_COMUNS))


def load_wordlist(caminho: Path) -> tuple[str, ...]:
    """Carrega uma lista alternativa fornecida pelo usuário."""
    palavras = _linhas_uteis(caminho.read_text(encoding="utf-8"))
    if len(palavras) < 64:
        raise ValueError("uma lista de palavras útil precisa de ao menos 64 entradas")
    return tuple(dict.fromkeys(palavras))
