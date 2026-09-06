"""Cifragem simétrica do corpo do cofre.

O corpo é cifrado com AES-256 em modo CBC e autenticado à parte, por
HMAC-SHA256 (esquema encrypt-then-MAC, ver crypto/mac.py). Separar
confidencialidade de autenticidade é proposital: permite verificar a
integridade de cada bloco antes de decifrar qualquer coisa, o que reduz a
superfície exposta a um arquivo malicioso.

O cabeçalho guarda um identificador de cifra de 1 byte. Hoje só existe uma
suíte (AES-256-CBC), então o identificador não escolhe nada -- ele só faz o
formato recusar de imediato um arquivo gravado por uma suíte futura
desconhecida, em vez de tentar decifrá-lo com a suíte errada.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from arca.model.erros import ErroFormatoInvalido

TAMANHO_IV = 16
TAMANHO_CHAVE = 32

IDENTIFICADOR_AES256_CBC = 1
ROTULO_AES256_CBC = "AES-256 (CBC)"


def validar_identificador_de_cifra(valor: int) -> int:
    if valor != IDENTIFICADOR_AES256_CBC:
        raise ErroFormatoInvalido(f"cifra desconhecida no cabeçalho: {valor}")
    return valor


def novo_iv() -> bytes:
    """Sorteia um IV. O sal do KDF também muda a cada gravação, então a
    chave de cifragem nunca se repete sob o mesmo IV."""
    return os.urandom(TAMANHO_IV)


def _validar(chave: bytes, iv: bytes) -> None:
    if len(chave) != TAMANHO_CHAVE:
        raise ErroFormatoInvalido("a chave de cifragem deve ter 32 bytes")
    if len(iv) != TAMANHO_IV:
        raise ErroFormatoInvalido("o IV deve ter 16 bytes")


def criptografar(chave: bytes, iv: bytes, claro: bytes) -> bytes:
    _validar(chave, iv)
    preenchedor = padding.PKCS7(algorithms.AES.block_size).padder()
    bloco = preenchedor.update(claro) + preenchedor.finalize()
    ctx = Cipher(algorithms.AES(chave), modes.CBC(iv)).encryptor()
    return ctx.update(bloco) + ctx.finalize()


def descriptografar(chave: bytes, iv: bytes, cifrado: bytes) -> bytes:
    _validar(chave, iv)
    if len(cifrado) % 16 != 0:
        raise ErroFormatoInvalido("texto cifrado não é múltiplo do bloco AES")
    ctx = Cipher(algorithms.AES(chave), modes.CBC(iv)).decryptor()
    bloco = ctx.update(cifrado) + ctx.finalize()
    removedor = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        return removedor.update(bloco) + removedor.finalize()
    except ValueError as exc:
        # Com o HMAC já verificado, isso só ocorre em bug de gravação.
        raise ErroFormatoInvalido("preenchimento PKCS#7 inválido") from exc
