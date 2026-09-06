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

from arca.crypto.cifras import (
    IDENTIFICADOR_AES256_CBC,
    ROTULO_AES256_CBC,
    TAMANHO_IV,
    validar_identificador_de_cifra,
)
from arca.crypto.fluxo import TipoDeCifraDeFluxo
from arca.crypto.kdf import TAMANHO_SAL, ParametrosKdf
from arca.model.erros import ErroDeIntegridade, ErroFormatoInvalido, ErroVersaoNaoSuportada

ASSINATURA = b"ARCA\x1a\x0d\x0a\x00"
VERSAO_MAIOR = 1
VERSAO_MENOR = 0

TAMANHO_RESUMO = 32

_PREAMBULO = struct.Struct("<8sHH")
_TLV = struct.Struct("<BI")
_LIMITE_CAMPO = 1024 * 1024
_PRIMEIRO_ID_OPCIONAL = 0x80


class Compressao(IntEnum):
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
class Cabecalho:
    """Cabeçalho externo, gravado em texto claro."""

    cifra: int = IDENTIFICADOR_AES256_CBC
    compressao: Compressao = Compressao.GZIP
    kdf: ParametrosKdf = field(default_factory=ParametrosKdf)
    sal_mestre: bytes = b""
    iv: bytes = b""
    versao: tuple[int, int] = (VERSAO_MAIOR, VERSAO_MENOR)

    def para_bytes(self) -> bytes:
        if len(self.sal_mestre) != TAMANHO_SAL:
            raise ErroFormatoInvalido("o sal mestre deve ter 32 bytes")
        if len(self.iv) != TAMANHO_IV:
            raise ErroFormatoInvalido("o IV deve ter 16 bytes")
        return b"".join([
            _PREAMBULO.pack(ASSINATURA, *self.versao),
            _campo(CampoExterno.CIFRA, bytes([self.cifra])),
            _campo(CampoExterno.COMPRESSAO, bytes([self.compressao])),
            _campo(CampoExterno.PARAMETROS_KDF, self.kdf.para_bytes()),
            _campo(CampoExterno.SAL_MESTRE, self.sal_mestre),
            _campo(CampoExterno.IV, self.iv),
            _campo(CampoExterno.FIM, b""),
        ])

    def descrever(self) -> str:
        return f"{ROTULO_AES256_CBC} · {self.kdf.descrever()}"


@dataclass(slots=True)
class CabecalhoInterno:
    """Cabeçalho interno, já dentro da área cifrada."""

    tipo_da_cifra_de_fluxo: TipoDeCifraDeFluxo = TipoDeCifraDeFluxo.CHACHA20
    chave_da_cifra_de_fluxo: bytes = b""

    def para_bytes(self) -> bytes:
        if (self.tipo_da_cifra_de_fluxo is not TipoDeCifraDeFluxo.NENHUMA
                and len(self.chave_da_cifra_de_fluxo) != 32):
            raise ErroFormatoInvalido("a chave da cifra de fluxo deve ter 32 bytes")
        return b"".join([
            _campo(CampoInterno.CIFRA_DE_FLUXO, bytes([self.tipo_da_cifra_de_fluxo])),
            _campo(CampoInterno.CHAVE_DE_FLUXO, self.chave_da_cifra_de_fluxo),
            _campo(CampoInterno.FIM, b""),
        ])


def _campo(identificador: int, valor: bytes) -> bytes:
    return _TLV.pack(identificador, len(valor)) + valor


def _ler_campos(origem: BinaryIO, contexto: str) -> dict[int, bytes]:
    campos: dict[int, bytes] = {}
    while True:
        cru = origem.read(_TLV.size)
        if len(cru) != _TLV.size:
            raise ErroFormatoInvalido(f"{contexto} truncado")
        identificador, tamanho = _TLV.unpack(cru)
        if tamanho > _LIMITE_CAMPO:
            raise ErroFormatoInvalido(f"{contexto}: campo {identificador} grande demais")
        valor = origem.read(tamanho)
        if len(valor) != tamanho:
            raise ErroFormatoInvalido(f"{contexto} truncado no campo {identificador}")
        if identificador == 0:
            return campos
        campos[identificador] = valor


def _obrigatorio(campos: dict[int, bytes], campo: IntEnum, contexto: str) -> bytes:
    try:
        return campos[campo.value]
    except KeyError:
        raise ErroFormatoInvalido(
            f"{contexto}: campo obrigatório ausente ({campo.name})"
        ) from None


def _rejeitar_desconhecidos(campos: dict[int, bytes], conhecidos: type[IntEnum],
                            contexto: str) -> None:
    validos = {membro.value for membro in conhecidos}
    for identificador in campos:
        if identificador in validos or identificador >= _PRIMEIRO_ID_OPCIONAL:
            continue
        raise ErroFormatoInvalido(f"{contexto}: campo obrigatório desconhecido ({identificador})")


def ler_cabecalho(origem: BinaryIO) -> tuple[Cabecalho, bytes]:
    """Lê o cabeçalho externo e devolve também seus bytes crus, para o HMAC."""
    inicio = origem.tell()
    preambulo = origem.read(_PREAMBULO.size)
    if len(preambulo) != _PREAMBULO.size:
        raise ErroFormatoInvalido("arquivo pequeno demais para ser um cofre Arca")

    assinatura, maior, menor = _PREAMBULO.unpack(preambulo)
    if assinatura != ASSINATURA:
        raise ErroFormatoInvalido("assinatura inválida: este arquivo não é um cofre Arca")
    if maior > VERSAO_MAIOR:
        raise ErroVersaoNaoSuportada(
            f"cofre gravado na versão {maior}.{menor} do formato; "
            f"esta build lê até {VERSAO_MAIOR}.{VERSAO_MENOR}"
        )

    campos = _ler_campos(origem, "cabeçalho")
    _rejeitar_desconhecidos(campos, CampoExterno, "cabeçalho")

    cabecalho = Cabecalho(
        cifra=validar_identificador_de_cifra(
            _um_byte(_obrigatorio(campos, CampoExterno.CIFRA, "cabeçalho"))
        ),
        compressao=_compressao(
            _um_byte(_obrigatorio(campos, CampoExterno.COMPRESSAO, "cabeçalho"))
        ),
        kdf=ParametrosKdf.de_bytes(
            _obrigatorio(campos, CampoExterno.PARAMETROS_KDF, "cabeçalho")
        ),
        sal_mestre=_obrigatorio(campos, CampoExterno.SAL_MESTRE, "cabeçalho"),
        iv=_obrigatorio(campos, CampoExterno.IV, "cabeçalho"),
        versao=(maior, menor),
    )
    if len(cabecalho.sal_mestre) != TAMANHO_SAL:
        raise ErroFormatoInvalido("sal mestre com tamanho inválido")
    if len(cabecalho.iv) != TAMANHO_IV:
        raise ErroFormatoInvalido("IV com tamanho inválido")

    fim = origem.tell()
    origem.seek(inicio)
    crus = origem.read(fim - inicio)
    return cabecalho, crus


def ler_cabecalho_interno(dados: bytes) -> tuple[CabecalhoInterno, bytes]:
    """Separa o cabeçalho interno do payload que vem logo depois dele."""
    fluxo = BytesIO(dados)
    campos = _ler_campos(fluxo, "cabeçalho interno")
    _rejeitar_desconhecidos(campos, CampoInterno, "cabeçalho interno")

    bruto = _um_byte(_obrigatorio(campos, CampoInterno.CIFRA_DE_FLUXO, "cabeçalho interno"))
    try:
        tipo_da_cifra = TipoDeCifraDeFluxo(bruto)
    except ValueError as exc:
        raise ErroFormatoInvalido(f"cifra de fluxo interna desconhecida: {bruto}") from exc

    chave = campos.get(CampoInterno.CHAVE_DE_FLUXO.value, b"")
    if tipo_da_cifra is not TipoDeCifraDeFluxo.NENHUMA and len(chave) != 32:
        raise ErroFormatoInvalido("chave da cifra de fluxo com tamanho inválido")
    return CabecalhoInterno(tipo_da_cifra, chave), dados[fluxo.tell():]


def resumo_do_cabecalho(crus: bytes) -> bytes:
    return hashlib.sha256(crus).digest()


def mac_do_cabecalho(crus: bytes, chave_do_cabecalho: bytes) -> bytes:
    return hmac.new(chave_do_cabecalho, crus, hashlib.sha256).digest()


def verificar_resumo_do_cabecalho(crus: bytes, resumo: bytes) -> None:
    if not hmac.compare_digest(resumo_do_cabecalho(crus), resumo):
        raise ErroFormatoInvalido("cabeçalho corrompido: o resumo SHA-256 não confere")


def verificar_mac_do_cabecalho(crus: bytes, mac: bytes, chave_do_cabecalho: bytes) -> None:
    if not hmac.compare_digest(mac_do_cabecalho(crus, chave_do_cabecalho), mac):
        raise ErroDeIntegridade("credenciais incorretas ou cabeçalho adulterado")


def _um_byte(valor: bytes) -> int:
    if len(valor) != 1:
        raise ErroFormatoInvalido("campo de um byte com tamanho inválido")
    return valor[0]


def _compressao(valor: int) -> Compressao:
    try:
        return Compressao(valor)
    except ValueError as exc:
        raise ErroFormatoInvalido(f"modo de compressão desconhecido: {valor}") from exc
