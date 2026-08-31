"""Cifras simétricas aceitas pelo formato Arca.

O corpo do cofre é cifrado por uma destas suítes e autenticado à parte, por
HMAC-SHA256 (esquema encrypt-then-MAC, ver core/hmacblock.py). Separar
confidencialidade de autenticidade é proposital: permite verificar a
integridade de cada bloco antes de decifrar qualquer coisa, o que reduz a
superfície exposta a um arquivo malicioso.
"""

from __future__ import annotations

import os
from enum import IntEnum

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from arca.model.errors import VaultFormatError

TAMANHO_IV = 16
TAMANHO_CHAVE = 32


class CipherId(IntEnum):
    AES256_CBC = 1
    CHACHA20 = 2

    @property
    def rotulo(self) -> str:
        return {
            CipherId.AES256_CBC: "AES-256 (CBC)",
            CipherId.CHACHA20: "ChaCha20",
        }[self]


def parse_cipher_id(valor: int) -> CipherId:
    try:
        return CipherId(valor)
    except ValueError as exc:
        raise VaultFormatError(f"cifra desconhecida no cabeçalho: {valor}") from exc


def new_iv(cipher: CipherId) -> bytes:
    """Sorteia um IV válido para a suíte.

    No ChaCha20 os 8 primeiros bytes formam o contador de bloco e precisam
    começar zerados; os 8 restantes são o nonce. Como o sal do KDF é
    renovado a cada gravação, a chave também muda, e o nonce de 64 bits
    nunca é reaproveitado sob a mesma chave.
    """
    if cipher is CipherId.CHACHA20:
        return b"\x00" * 8 + os.urandom(8)
    return os.urandom(TAMANHO_IV)


def _validar(chave: bytes, iv: bytes) -> None:
    if len(chave) != TAMANHO_CHAVE:
        raise VaultFormatError("a chave de cifragem deve ter 32 bytes")
    if len(iv) != TAMANHO_IV:
        raise VaultFormatError("o IV deve ter 16 bytes")


def encrypt(cipher: CipherId, chave: bytes, iv: bytes, claro: bytes) -> bytes:
    _validar(chave, iv)
    if cipher is CipherId.AES256_CBC:
        preenchedor = padding.PKCS7(algorithms.AES.block_size).padder()
        bloco = preenchedor.update(claro) + preenchedor.finalize()
        ctx = Cipher(algorithms.AES(chave), modes.CBC(iv)).encryptor()
        return ctx.update(bloco) + ctx.finalize()
    ctx = Cipher(algorithms.ChaCha20(chave, iv), mode=None).encryptor()
    return ctx.update(claro)


def decrypt(cipher: CipherId, chave: bytes, iv: bytes, cifrado: bytes) -> bytes:
    _validar(chave, iv)
    if cipher is CipherId.AES256_CBC:
        if len(cifrado) % 16 != 0:
            raise VaultFormatError("texto cifrado não é múltiplo do bloco AES")
        ctx = Cipher(algorithms.AES(chave), modes.CBC(iv)).decryptor()
        bloco = ctx.update(cifrado) + ctx.finalize()
        removedor = padding.PKCS7(algorithms.AES.block_size).unpadder()
        try:
            return removedor.update(bloco) + removedor.finalize()
        except ValueError as exc:
            # Com o HMAC já verificado, isso só ocorre em bug de gravação.
            raise VaultFormatError("preenchimento PKCS#7 inválido") from exc
    ctx = Cipher(algorithms.ChaCha20(chave, iv), mode=None).decryptor()
    return ctx.update(cifrado)
