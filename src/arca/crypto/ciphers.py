"""Cifragem simétrica do corpo do cofre.

O corpo é cifrado com AES-256 em modo CBC e autenticado à parte, por
HMAC-SHA256 (esquema encrypt-then-MAC, ver crypto/mac.py). Separar
confidencialidade de autenticidade é proposital: permite verificar a
integridade de cada bloco antes de decifrar qualquer coisa, o que reduz a
superfície exposta a um arquivo malicioso.

O cabeçalho guarda um identificador de cifra, ainda que hoje exista um só.
O campo não é desperdício: é o que permitiria trocar a suíte no futuro sem
invalidar os cofres já gravados, e é o que faz um arquivo com identificador
desconhecido ser recusado de imediato, em vez de decifrado com a suíte errada.
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

    @property
    def rotulo(self) -> str:
        return "AES-256 (CBC)"


def parse_cipher_id(valor: int) -> CipherId:
    try:
        return CipherId(valor)
    except ValueError as exc:
        raise VaultFormatError(f"cifra desconhecida no cabeçalho: {valor}") from exc


def new_iv() -> bytes:
    """Sorteia um IV. O sal do KDF também muda a cada gravação, então a
    chave de cifragem nunca se repete sob o mesmo IV."""
    return os.urandom(TAMANHO_IV)


def _validar(chave: bytes, iv: bytes) -> None:
    if len(chave) != TAMANHO_CHAVE:
        raise VaultFormatError("a chave de cifragem deve ter 32 bytes")
    if len(iv) != TAMANHO_IV:
        raise VaultFormatError("o IV deve ter 16 bytes")


def encrypt(chave: bytes, iv: bytes, claro: bytes) -> bytes:
    _validar(chave, iv)
    preenchedor = padding.PKCS7(algorithms.AES.block_size).padder()
    bloco = preenchedor.update(claro) + preenchedor.finalize()
    ctx = Cipher(algorithms.AES(chave), modes.CBC(iv)).encryptor()
    return ctx.update(bloco) + ctx.finalize()


def decrypt(chave: bytes, iv: bytes, cifrado: bytes) -> bytes:
    _validar(chave, iv)
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
