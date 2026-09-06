"""Leitura e gravação do arquivo .arca.

Este módulo é o único ponto do projeto que conhece o formato completo. A
sequência de bytes é:

    cabeçalho externo                   (texto claro, TLV)
    SHA-256 do cabeçalho                (32 bytes)
    HMAC-SHA256 do cabeçalho            (32 bytes)
    fluxo de blocos autenticados        (ver crypto/mac.py)
        -> ao ser decifrado, contém:
           cabeçalho interno            (TLV)
           payload JSON                 (comprimido, se o cabeçalho disser)

Decisões que valem registro:

* o sal do KDF e o IV são sorteados de novo a cada gravação. Isso troca a
  chave de cifragem a cada salvamento e elimina qualquer chance de reúso de
  IV sob a mesma chave -- o custo é uma derivação Argon2id por save;
* a gravação é atômica: escreve em arquivo temporário no mesmo diretório,
  força a descarga em disco e só então substitui o original. Uma queda de
  energia no meio do processo deixa o cofre antigo intacto;
* a verificação acontece antes da decifragem. Um cofre adulterado é
  rejeitado sem que um único byte de texto cifrado chegue à cifra.

As funções de baixo nível (`criptografar`, `descriptografar`, `derivar_chaves`
etc.) são apenas apelidos em português para as funções equivalentes da camada
`crypto` -- as ferramentas de fato moram lá, isoladas por serem o núcleo
criptográfico do projeto (ver `crypto/__init__.py`).
"""

from __future__ import annotations

import gzip
import os
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from tempfile import NamedTemporaryFile

from arca.crypto.cifras import criptografar, descriptografar, novo_iv
from arca.crypto.fluxo import TipoDeCifraDeFluxo, construir_cifra_de_fluxo
from arca.crypto.kdf import TAMANHO_SAL, ChavesDoCofre, ParametrosKdf, chave_composta
from arca.crypto.kdf import derivar as derivar_chaves
from arca.crypto.mac import escrever_blocos, ler_blocos
from arca.crypto.segredo import BytesSecretos
from arca.model import codificador
from arca.model.cabecalho import (
    TAMANHO_RESUMO,
    Cabecalho,
    CabecalhoInterno,
    Compressao,
    ler_cabecalho,
    ler_cabecalho_interno,
    mac_do_cabecalho,
    resumo_do_cabecalho,
    verificar_mac_do_cabecalho,
    verificar_resumo_do_cabecalho,
)
from arca.model.cofre import Cofre, agora
from arca.model.erros import (
    ErroArca,
    ErroCredenciaisInvalidas,
    ErroDeIntegridade,
    ErroFormatoInvalido,
)

SUFIXO_BACKUP = ".bak"


@dataclass(slots=True)
class Credenciais:
    """Fator de autenticação de um cofre: a senha mestra."""

    senha: BytesSecretos | None = None

    @classmethod
    def a_partir_de(cls, senha: str | None) -> Credenciais:
        return cls(senha=BytesSecretos.a_partir_de_texto(senha) if senha is not None else None)

    def para_chave_composta(self) -> bytes:
        if self.senha is None:
            raise ErroCredenciaisInvalidas("informe a senha mestra")
        return chave_composta(self.senha.valor())

    def descrever(self) -> str:
        return "senha mestra" if self.senha is not None else "nenhum fator"

    def apagar(self) -> None:
        if self.senha is not None:
            self.senha.apagar()


@dataclass(slots=True)
class OpcoesDeGravacao:
    compressao: Compressao = Compressao.GZIP
    kdf: ParametrosKdf = field(default_factory=ParametrosKdf)
    proteger_campos: bool = True
    fazer_backup: bool = True

    @classmethod
    def a_partir_do_cabecalho(cls, cabecalho: Cabecalho, **ajustes: object) -> OpcoesDeGravacao:
        """Reaproveita as escolhas do arquivo aberto ao salvar de novo."""
        base = cls(
            compressao=cabecalho.compressao,
            kdf=cabecalho.kdf,
        )
        for nome, valor in ajustes.items():
            setattr(base, nome, valor)
        return base


@dataclass(slots=True)
class CofreCarregado:
    cofre: Cofre
    cabecalho: Cabecalho
    caminho: Path


def salvar(caminho: Path, cofre: Cofre, credenciais: Credenciais,
           opcoes: OpcoesDeGravacao | None = None) -> Cabecalho:
    """Grava o cofre de forma atômica e devolve o cabeçalho usado."""
    opcoes = opcoes or OpcoesDeGravacao()
    cabecalho = Cabecalho(
        compressao=opcoes.compressao,
        kdf=opcoes.kdf,
        sal_mestre=os.urandom(TAMANHO_SAL),
        iv=novo_iv(),
    )
    composta = credenciais.para_chave_composta()
    chaves = derivar_chaves(composta, cabecalho.sal_mestre, cabecalho.kdf)

    cofre.metadados.salvo_em = agora()
    corpo = _montar_corpo(cofre, cabecalho, opcoes.proteger_campos)
    corpo_cifrado = criptografar(chaves.cifragem, cabecalho.iv, corpo)

    crus = cabecalho.para_bytes()
    conteudo = BytesIO()
    conteudo.write(crus)
    conteudo.write(resumo_do_cabecalho(crus))
    conteudo.write(mac_do_cabecalho(crus, chaves.chave_do_cabecalho()))
    escrever_blocos(conteudo, corpo_cifrado, chaves.semente_hmac)

    _gravar_atomico(caminho, conteudo.getvalue(), opcoes.fazer_backup)
    return cabecalho


def carregar(caminho: Path, credenciais: Credenciais) -> CofreCarregado:
    """Abre um cofre existente, verificando integridade antes de decifrar."""
    try:
        bruto = caminho.read_bytes()
    except OSError as exc:
        raise ErroArca(f"não foi possível abrir {caminho}: {exc}") from exc

    fluxo = BytesIO(bruto)
    cabecalho, crus = ler_cabecalho(fluxo)
    fluxo.seek(len(crus))

    resumo = _ler_exato(fluxo, TAMANHO_RESUMO, "o resumo do cabeçalho")
    verificar_resumo_do_cabecalho(crus, resumo)
    mac = _ler_exato(fluxo, TAMANHO_RESUMO, "o HMAC do cabeçalho")

    composta = credenciais.para_chave_composta()
    chaves = derivar_chaves(composta, cabecalho.sal_mestre, cabecalho.kdf)
    try:
        verificar_mac_do_cabecalho(crus, mac, chaves.chave_do_cabecalho())
    except ErroDeIntegridade as exc:
        # Neste ponto o cabeçalho já passou pelo SHA-256, então a hipótese
        # esmagadoramente mais provável é credencial errada, e não adulteração.
        raise ErroCredenciaisInvalidas("senha mestra incorreta") from exc

    corpo_cifrado = ler_blocos(fluxo, chaves.semente_hmac)
    corpo = descriptografar(chaves.cifragem, cabecalho.iv, corpo_cifrado)
    cofre = _desmontar_corpo(corpo, cabecalho)
    return CofreCarregado(cofre=cofre, cabecalho=cabecalho, caminho=caminho)


def inspecionar(caminho: Path) -> Cabecalho:
    """Lê apenas o cabeçalho externo, sem exigir credenciais."""
    with caminho.open("rb") as arquivo:
        cabecalho, crus = ler_cabecalho(arquivo)
        arquivo.seek(len(crus))
        verificar_resumo_do_cabecalho(
            crus, _ler_exato(arquivo, TAMANHO_RESUMO, "o resumo do cabeçalho")
        )
    return cabecalho


def trocar_credenciais(caminho: Path, atuais: Credenciais, novas: Credenciais,
                       opcoes: OpcoesDeGravacao | None = None) -> None:
    """Reescreve o cofre sob novos fatores de autenticação."""
    aberto = carregar(caminho, atuais)
    escolhas = opcoes or OpcoesDeGravacao.a_partir_do_cabecalho(aberto.cabecalho)
    salvar(caminho, aberto.cofre, novas, escolhas)


# --------------------------------------------------------------------------
# Corpo cifrado
# --------------------------------------------------------------------------

def _montar_corpo(cofre: Cofre, cabecalho: Cabecalho, proteger: bool) -> bytes:
    interno = CabecalhoInterno(
        tipo_da_cifra_de_fluxo=(
            TipoDeCifraDeFluxo.CHACHA20 if proteger else TipoDeCifraDeFluxo.NENHUMA
        ),
        chave_da_cifra_de_fluxo=os.urandom(32) if proteger else b"",
    )
    cifra = construir_cifra_de_fluxo(
        interno.tipo_da_cifra_de_fluxo, interno.chave_da_cifra_de_fluxo
    )
    payload = codificador.serializar_conteudo(cofre, cifra)
    if cabecalho.compressao is Compressao.GZIP:
        # mtime fixo: o formato não deve vazar o horário do salvamento em claro
        # nem produzir diffs espúrios entre duas gravações do mesmo conteúdo.
        payload = gzip.compress(payload, compresslevel=6, mtime=0)
    return interno.para_bytes() + payload


def _desmontar_corpo(corpo: bytes, cabecalho: Cabecalho) -> Cofre:
    interno, payload = ler_cabecalho_interno(corpo)
    if cabecalho.compressao is Compressao.GZIP:
        try:
            payload = gzip.decompress(payload)
        except (OSError, EOFError) as exc:
            raise ErroFormatoInvalido(f"payload comprimido ilegível: {exc}") from exc
    cifra = construir_cifra_de_fluxo(
        interno.tipo_da_cifra_de_fluxo, interno.chave_da_cifra_de_fluxo
    )
    return codificador.carregar_conteudo(payload, cifra)


# --------------------------------------------------------------------------
# Escrita em disco
# --------------------------------------------------------------------------

def _gravar_atomico(destino: Path, conteudo: bytes, fazer_backup: bool) -> None:
    destino.parent.mkdir(parents=True, exist_ok=True)
    if fazer_backup and destino.exists():
        backup = destino.with_suffix(destino.suffix + SUFIXO_BACKUP)
        backup.write_bytes(destino.read_bytes())

    temporario: Path | None = None
    try:
        with NamedTemporaryFile(dir=destino.parent, prefix=".arca-", suffix=".tmp",
                                delete=False) as arquivo:
            temporario = Path(arquivo.name)
            arquivo.write(conteudo)
            arquivo.flush()
            os.fsync(arquivo.fileno())
        os.replace(temporario, destino)
        temporario = None
    finally:
        if temporario is not None and temporario.exists():
            temporario.unlink(missing_ok=True)


def _ler_exato(fluxo: BytesIO, quantidade: int, o_que: str) -> bytes:
    dados = fluxo.read(quantidade)
    if len(dados) != quantidade:
        raise ErroFormatoInvalido(f"arquivo truncado ao ler {o_que}")
    return dados


__all__ = [
    "ChavesDoCofre",
    "CofreCarregado",
    "Credenciais",
    "OpcoesDeGravacao",
    "carregar",
    "inspecionar",
    "salvar",
    "trocar_credenciais",
]
