"""Cifra de fluxo usada para mascarar campos sensíveis.

São dois usos, com chaves independentes:

1. no payload gravado em disco, os campos marcados como protegidos são
   mascarados por este fluxo de chave antes de virarem base64. A chave vive no
   cabeçalho interno, ou seja, dentro da área já cifrada do arquivo. O ganho
   é que um payload descomprimido em memória, um core dump ou um arquivo
   temporário do sistema não expõem senhas em texto claro;
2. em memória, `ValorProtegido` usa uma chave aleatória por execução.

Como o fluxo de chave é sequencial, produtor e consumidor precisam percorrer
os campos exatamente na mesma ordem. Essa ordem é definida em
model/codificador.py.
"""

from __future__ import annotations

import hashlib
from enum import IntEnum

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


class TipoDeCifraDeFluxo(IntEnum):
    NENHUMA = 0
    CHACHA20 = 1


class CifraChaCha20:
    """Gerador ChaCha20 que mantém a posição entre chamadas."""

    def __init__(self, chave: bytes) -> None:
        if len(chave) != 32:
            raise ValueError("a chave da cifra de fluxo deve ter 32 bytes")
        semente = hashlib.sha512(chave).digest()
        # Os 8 primeiros bytes do IV são o contador de bloco: começam zerados.
        iv = b"\x00" * 8 + semente[32:40]
        self._ctx = Cipher(algorithms.ChaCha20(semente[:32], iv), mode=None).encryptor()

    def fluxo_de_chave(self, tamanho: int) -> bytes:
        return self._ctx.update(b"\x00" * tamanho)

    def processar(self, dados: bytes) -> bytes:
        """XOR com o fluxo de chave. Simétrico: aplicar duas vezes restaura o original."""
        return self._ctx.update(dados)


class CifraDeFluxoNula:
    """Implementação inerte, para quando a proteção interna está desligada."""

    def fluxo_de_chave(self, tamanho: int) -> bytes:
        return b"\x00" * tamanho

    def processar(self, dados: bytes) -> bytes:
        return dados


def construir_cifra_de_fluxo(tipo: int, chave: bytes) -> CifraChaCha20 | CifraDeFluxoNula:
    if tipo == TipoDeCifraDeFluxo.NENHUMA:
        return CifraDeFluxoNula()
    if tipo == TipoDeCifraDeFluxo.CHACHA20:
        return CifraChaCha20(chave)
    raise ValueError(f"cifra de fluxo interna desconhecida: {tipo}")
