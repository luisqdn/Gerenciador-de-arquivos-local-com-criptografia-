"""Cabeçalhos do arquivo .arca.

São dois, com papéis distintos:

* o cabeçalho externo fica em texto claro, porque descreve como decifrar o
  resto (suíte, IV, sal e parâmetros do KDF). Ele é apenas autenticado, por
  SHA-256 mais HMAC-SHA256, e a chave desse HMAC só existe depois que a senha
  correta passa pelo KDF. Alterar o cabeçalho para, por exemplo, rebaixar o
  custo do Argon2id derruba a verificação;
* o cabeçalho interno viaja dentro da área cifrada e guarda a chave da cifra
  de fluxo que mascara os campos protegidos do payload.

Ambos usam o mesmo formato TLV: identificador de 1 byte, tamanho de 4 bytes
em little-endian e o valor. O identificador 0 encerra a lista. Campos
desconhecidos com identificador a partir de 0x80 são ignorados na leitura, o
que abre espaço para extensões compatíveis; abaixo disso, são fatais.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from io import BytesIO
from typing import BinaryIO

from arca.core.ciphers import TAMANHO_IV, CipherId, parse_cipher_id
from arca.core.errors import IntegrityError, UnsupportedVersionError, VaultFormatError
from arca.core.kdf import KdfParameters
from arca.core.keys import TAMANHO_SAL
from arca.core.protectedstream import InnerStreamId

ASSINATURA = b"ARCA\x1a\x0d\x0a\x00"
VERSAO_MAIOR = 1
VERSAO_MENOR = 0

TAMANHO_RESUMO = 32

_PREAMBULO = struct.Struct("<8sHH")
_TLV = struct.Struct("<BI")
_LIMITE_CAMPO = 1024 * 1024
_PRIMEIRO_ID_OPCIONAL = 0x80


class Compression(IntEnum):
    NENHUMA = 0
    GZIP = 1


class CampoExterno(IntEnum):
    FIM = 0
    CIFRA = 1
    COMPRESSAO = 2
    PARAMETROS_KDF = 3
    SAL_MESTRE = 4
    IV = 5


class CampoInterno(IntEnum):
    FIM = 0
    CIFRA_DE_FLUXO = 1
    CHAVE_DE_FLUXO = 2


@dataclass(slots=True)
class VaultHeader:
    """Cabeçalho externo, gravado em texto claro."""

    cipher: CipherId = CipherId.AES256_CBC
    compression: Compression = Compression.GZIP
    kdf: KdfParameters = field(default_factory=KdfParameters)
    master_salt: bytes = b""
    iv: bytes = b""
    version: tuple[int, int] = (VERSAO_MAIOR, VERSAO_MENOR)

    def to_bytes(self) -> bytes:
        if len(self.master_salt) != TAMANHO_SAL:
            raise VaultFormatError("o sal mestre deve ter 32 bytes")
        if len(self.iv) != TAMANHO_IV:
            raise VaultFormatError("o IV deve ter 16 bytes")
        return b"".join([
            _PREAMBULO.pack(ASSINATURA, *self.version),
            _campo(CampoExterno.CIFRA, bytes([self.cipher])),
            _campo(CampoExterno.COMPRESSAO, bytes([self.compression])),
            _campo(CampoExterno.PARAMETROS_KDF, self.kdf.to_bytes()),
            _campo(CampoExterno.SAL_MESTRE, self.master_salt),
            _campo(CampoExterno.IV, self.iv),
            _campo(CampoExterno.FIM, b""),
        ])

    def describe(self) -> str:
        return f"{self.cipher.rotulo} · {self.kdf.describe()}"


@dataclass(slots=True)
class InnerHeader:
    """Cabeçalho interno, já dentro da área cifrada."""

    stream_id: InnerStreamId = InnerStreamId.CHACHA20
    stream_key: bytes = b""

    def to_bytes(self) -> bytes:
        if self.stream_id is not InnerStreamId.NONE and len(self.stream_key) != 32:
            raise VaultFormatError("a chave da cifra de fluxo deve ter 32 bytes")
        return b"".join([
            _campo(CampoInterno.CIFRA_DE_FLUXO, bytes([self.stream_id])),
            _campo(CampoInterno.CHAVE_DE_FLUXO, self.stream_key),
            _campo(CampoInterno.FIM, b""),
        ])


def _campo(identificador: int, valor: bytes) -> bytes:
    return _TLV.pack(identificador, len(valor)) + valor


def _ler_campos(origem: BinaryIO, contexto: str) -> dict[int, bytes]:
    campos: dict[int, bytes] = {}
    while True:
        cru = origem.read(_TLV.size)
        if len(cru) != _TLV.size:
            raise VaultFormatError(f"{contexto} truncado")
        identificador, tamanho = _TLV.unpack(cru)
        if tamanho > _LIMITE_CAMPO:
            raise VaultFormatError(f"{contexto}: campo {identificador} grande demais")
        valor = origem.read(tamanho)
        if len(valor) != tamanho:
            raise VaultFormatError(f"{contexto} truncado no campo {identificador}")
        if identificador == 0:
            return campos
        campos[identificador] = valor


def _obrigatorio(campos: dict[int, bytes], campo: IntEnum, contexto: str) -> bytes:
    try:
        return campos[campo.value]
    except KeyError:
        raise VaultFormatError(
            f"{contexto}: campo obrigatório ausente ({campo.name})"
        ) from None


def _rejeitar_desconhecidos(campos: dict[int, bytes], conhecidos: type[IntEnum],
                            contexto: str) -> None:
    validos = {membro.value for membro in conhecidos}
    for identificador in campos:
        if identificador in validos or identificador >= _PRIMEIRO_ID_OPCIONAL:
            continue
        raise VaultFormatError(f"{contexto}: campo obrigatório desconhecido ({identificador})")


def read_header(origem: BinaryIO) -> tuple[VaultHeader, bytes]:
    """Lê o cabeçalho externo e devolve também seus bytes crus, para o HMAC."""
    inicio = origem.tell()
    preambulo = origem.read(_PREAMBULO.size)
    if len(preambulo) != _PREAMBULO.size:
        raise VaultFormatError("arquivo pequeno demais para ser um cofre Arca")

    assinatura, maior, menor = _PREAMBULO.unpack(preambulo)
    if assinatura != ASSINATURA:
        raise VaultFormatError("assinatura inválida: este arquivo não é um cofre Arca")
    if maior > VERSAO_MAIOR:
        raise UnsupportedVersionError(
            f"cofre gravado na versão {maior}.{menor} do formato; "
            f"esta build lê até {VERSAO_MAIOR}.{VERSAO_MENOR}"
        )

    campos = _ler_campos(origem, "cabeçalho")
    _rejeitar_desconhecidos(campos, CampoExterno, "cabeçalho")

    cabecalho = VaultHeader(
        cipher=parse_cipher_id(_um_byte(_obrigatorio(campos, CampoExterno.CIFRA, "cabeçalho"))),
        compression=_compressao(
            _um_byte(_obrigatorio(campos, CampoExterno.COMPRESSAO, "cabeçalho"))
        ),
        kdf=KdfParameters.from_bytes(
            _obrigatorio(campos, CampoExterno.PARAMETROS_KDF, "cabeçalho")
        ),
        master_salt=_obrigatorio(campos, CampoExterno.SAL_MESTRE, "cabeçalho"),
        iv=_obrigatorio(campos, CampoExterno.IV, "cabeçalho"),
        version=(maior, menor),
    )
    if len(cabecalho.master_salt) != TAMANHO_SAL:
        raise VaultFormatError("sal mestre com tamanho inválido")
    if len(cabecalho.iv) != TAMANHO_IV:
        raise VaultFormatError("IV com tamanho inválido")

    fim = origem.tell()
    origem.seek(inicio)
    crus = origem.read(fim - inicio)
    return cabecalho, crus


def read_inner_header(dados: bytes) -> tuple[InnerHeader, bytes]:
    """Separa o cabeçalho interno do payload que vem logo depois dele."""
    fluxo = BytesIO(dados)
    campos = _ler_campos(fluxo, "cabeçalho interno")
    _rejeitar_desconhecidos(campos, CampoInterno, "cabeçalho interno")

    bruto = _um_byte(_obrigatorio(campos, CampoInterno.CIFRA_DE_FLUXO, "cabeçalho interno"))
    try:
        stream_id = InnerStreamId(bruto)
    except ValueError as exc:
        raise VaultFormatError(f"cifra de fluxo interna desconhecida: {bruto}") from exc

    chave = campos.get(CampoInterno.CHAVE_DE_FLUXO.value, b"")
    if stream_id is not InnerStreamId.NONE and len(chave) != 32:
        raise VaultFormatError("chave da cifra de fluxo com tamanho inválido")
    return InnerHeader(stream_id, chave), dados[fluxo.tell():]


def header_digest(crus: bytes) -> bytes:
    return hashlib.sha256(crus).digest()


def header_mac(crus: bytes, chave_do_cabecalho: bytes) -> bytes:
    return hmac.new(chave_do_cabecalho, crus, hashlib.sha256).digest()


def verify_header_digest(crus: bytes, resumo: bytes) -> None:
    if not hmac.compare_digest(header_digest(crus), resumo):
        raise VaultFormatError("cabeçalho corrompido: o resumo SHA-256 não confere")


def verify_header_mac(crus: bytes, mac: bytes, chave_do_cabecalho: bytes) -> None:
    if not hmac.compare_digest(header_mac(crus, chave_do_cabecalho), mac):
        raise IntegrityError("credenciais incorretas ou cabeçalho adulterado")


def _um_byte(valor: bytes) -> int:
    if len(valor) != 1:
        raise VaultFormatError("campo de um byte com tamanho inválido")
    return valor[0]


def _compressao(valor: int) -> Compression:
    try:
        return Compression(valor)
    except ValueError as exc:
        raise VaultFormatError(f"modo de compressão desconhecido: {valor}") from exc
