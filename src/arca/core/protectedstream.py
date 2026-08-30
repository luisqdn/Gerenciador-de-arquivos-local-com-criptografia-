"""Cifra de fluxo usada para mascarar campos sensíveis.

São dois usos, com chaves independentes:

1. no payload gravado em disco, os campos marcados como protegidos são
   mascarados por este keystream antes de virarem base64. A chave vive no
   cabeçalho interno, ou seja, dentro da área já cifrada do arquivo. O ganho
   é que um payload descomprimido em memória, um core dump ou um arquivo
   temporário do sistema não expõem senhas em texto claro;
2. em memória, `ProtectedValue` usa uma chave aleatória por execução.

Como o keystream é sequencial, produtor e consumidor precisam percorrer os
campos exatamente na mesma ordem. Essa ordem é definida em core/codec.py.
"""

from __future__ import annotations

import hashlib
from enum import IntEnum

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


class InnerStreamId(IntEnum):
    NONE = 0
    CHACHA20 = 1


class KeystreamCipher:
    """Gerador ChaCha20 que mantém a posição entre chamadas."""

    def __init__(self, chave: bytes) -> None:
        if len(chave) != 32:
            raise ValueError("a chave do keystream deve ter 32 bytes")
        semente = hashlib.sha512(chave).digest()
        # Os 8 primeiros bytes do IV são o contador de bloco: começam zerados.
        iv = b"\x00" * 8 + semente[32:40]
        self._ctx = Cipher(algorithms.ChaCha20(semente[:32], iv), mode=None).encryptor()

    def keystream(self, tamanho: int) -> bytes:
        return self._ctx.update(b"\x00" * tamanho)

    def process(self, dados: bytes) -> bytes:
        """XOR com o keystream. Simétrico: aplicar duas vezes restaura o original."""
        return self._ctx.update(dados)


class NullStreamCipher:
    """Implementação inerte, para quando a proteção interna está desligada."""

    def keystream(self, tamanho: int) -> bytes:
        return b"\x00" * tamanho

    def process(self, dados: bytes) -> bytes:
        return dados


def build_stream_cipher(stream_id: int, chave: bytes) -> KeystreamCipher | NullStreamCipher:
    if stream_id == InnerStreamId.NONE:
        return NullStreamCipher()
    if stream_id == InnerStreamId.CHACHA20:
        return KeystreamCipher(chave)
    raise ValueError(f"cifra de fluxo interna desconhecida: {stream_id}")
