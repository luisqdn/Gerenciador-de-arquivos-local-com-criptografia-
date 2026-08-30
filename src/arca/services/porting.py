"""Importação e exportação em CSV.

O CSV existe por dois motivos concretos: trazer dados de outro gerenciador e
permitir que o usuário saia do Arca quando quiser. Um cofre que aprisiona os
dados do dono é um cofre pior, não melhor.

O arquivo produzido não tem proteção nenhuma -- senhas em texto puro, legíveis
por qualquer processo com acesso ao disco. A função de exportação exige que o
chamador confirme isso explicitamente, para que nenhuma interface exporte por
acidente, e `secure_delete` fica disponível para o descarte posterior.
"""

from __future__ import annotations

import csv
import os
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from arca.core.errors import ArcaError
from arca.core.model import Entry, Group, Vault
from arca.core.secret import ProtectedValue

COLUNAS = ["grupo", "titulo", "usuario", "senha", "url", "notas", "etiquetas", "expira_em"]

# Cabeçalhos aceitos na importação, incluindo os de outros gerenciadores.
_SINONIMOS = {
    "grupo": {"grupo", "group", "pasta", "folder", "category", "categoria"},
    "titulo": {"titulo", "título", "title", "name", "nome", "account", "conta"},
    "usuario": {"usuario", "usuário", "username", "user", "login", "e-mail", "email"},
    "senha": {"senha", "password", "pass", "pwd"},
    "url": {"url", "site", "website", "endereco", "endereço", "link"},
    "notas": {"notas", "notes", "comment", "comentario", "comentário", "observacoes"},
    "etiquetas": {"etiquetas", "tags", "labels", "marcadores"},
    "expira_em": {"expira_em", "expires", "expiry", "validade"},
}


@dataclass(slots=True)
class ImportReport:
    imported: int = 0
    skipped: int = 0
    problems: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.problems is None:
            self.problems = []

    def summary(self) -> str:
        texto = f"{self.imported} entrada(s) importada(s)"
        if self.skipped:
            texto += f", {self.skipped} ignorada(s)"
        return texto


def export_csv(cofre: Vault, destino: Path, confirmado: bool = False,
               incluir_lixeira: bool = False) -> int:
    """Grava todas as entradas em texto puro. Devolve quantas foram gravadas."""
    if not confirmado:
        raise ArcaError(
            "a exportação grava as senhas em texto puro; "
            "confirme explicitamente para prosseguir"
        )
    entradas = [
        e for e in cofre.entries()
        if incluir_lixeira or not cofre.is_in_recycle_bin(e)
    ]
    destino.parent.mkdir(parents=True, exist_ok=True)
    with destino.open("w", encoding="utf-8", newline="") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=COLUNAS)
        escritor.writeheader()
        for entrada in entradas:
            escritor.writerow(_linha_de(entrada))
    _restringir_permissoes(destino)
    return len(entradas)


def import_csv(cofre: Vault, origem: Path, destino: Group | None = None,
               usar_coluna_grupo: bool = True) -> ImportReport:
    """Lê um CSV e acrescenta as entradas ao cofre."""
    relatorio = ImportReport()
    raiz = destino or cofre.root

    with origem.open("r", encoding="utf-8-sig", newline="") as arquivo:
        amostra = arquivo.read(4096)
        arquivo.seek(0)
        leitor = csv.DictReader(arquivo, dialect=_detectar_dialeto(amostra))
        if not leitor.fieldnames:
            raise ArcaError("o arquivo CSV não tem linha de cabeçalho")
        mapa = _mapear_colunas(leitor.fieldnames)
        if "titulo" not in mapa and "usuario" not in mapa:
            raise ArcaError(
                "não foi possível identificar as colunas; esperado ao menos "
                "uma coluna de título ou de usuário"
            )

        for numero, linha in enumerate(leitor, start=2):
            try:
                entrada = _entrada_de(linha, mapa)
            except ValueError as exc:
                relatorio.skipped += 1
                relatorio.problems.append(f"linha {numero}: {exc}")
                continue
            if not entrada.title and not entrada.username:
                relatorio.skipped += 1
                continue
            grupo = raiz
            if usar_coluna_grupo and (caminho := _valor(linha, mapa, "grupo")):
                grupo = cofre.group_by_path(caminho, criar=True) or raiz
            grupo.add_entry(entrada)
            relatorio.imported += 1
    return relatorio


def secure_delete(caminho: Path, passagens: int = 1) -> None:
    """Sobrescreve e remove um arquivo exportado.

    Em SSDs e sistemas com journaling a sobrescrita não garante a destruição
    dos dados: o controlador pode ter escrito em outra página física. Serve
    como higiene, e não como garantia -- para descarte real, o caminho é
    manter o disco cifrado desde o início.
    """
    if not caminho.exists():
        return
    tamanho = caminho.stat().st_size
    with caminho.open("r+b") as arquivo:
        for _ in range(max(1, passagens)):
            arquivo.seek(0)
            arquivo.write(os.urandom(tamanho))
            arquivo.flush()
            os.fsync(arquivo.fileno())
    caminho.unlink()


# --------------------------------------------------------------------------
# Auxiliares
# --------------------------------------------------------------------------

def _linha_de(entrada: Entry) -> dict[str, str]:
    return {
        "grupo": entrada.parent.path() if entrada.parent else "",
        "titulo": entrada.title,
        "usuario": entrada.username,
        "senha": entrada.password.reveal(),
        "url": entrada.url,
        "notas": entrada.notes,
        "etiquetas": ", ".join(entrada.tags),
        "expira_em": (
            entrada.times.expires_at.date().isoformat() if entrada.times.expires_at else ""
        ),
    }


def _entrada_de(linha: dict[str, str], mapa: dict[str, str]) -> Entry:
    entrada = Entry(
        title=_valor(linha, mapa, "titulo"),
        username=_valor(linha, mapa, "usuario"),
        password=ProtectedValue(_valor(linha, mapa, "senha")),
        url=_valor(linha, mapa, "url"),
        notes=_valor(linha, mapa, "notas"),
    )
    etiquetas = _valor(linha, mapa, "etiquetas")
    if etiquetas:
        entrada.tags = [t.strip() for t in etiquetas.replace(";", ",").split(",") if t.strip()]
    validade = _valor(linha, mapa, "expira_em")
    if validade:
        entrada.times.expires_at = _data(validade)
    return entrada


def _valor(linha: dict[str, str], mapa: dict[str, str], campo: str) -> str:
    coluna = mapa.get(campo)
    if coluna is None:
        return ""
    return (linha.get(coluna) or "").strip()


def _mapear_colunas(cabecalhos: Iterable[str]) -> dict[str, str]:
    mapa: dict[str, str] = {}
    for cabecalho in cabecalhos:
        chave = cabecalho.strip().casefold()
        for campo, aceitos in _SINONIMOS.items():
            if chave in aceitos and campo not in mapa:
                mapa[campo] = cabecalho
                break
    return mapa


def _detectar_dialeto(amostra: str) -> type[csv.Dialect] | csv.Dialect:
    try:
        return csv.Sniffer().sniff(amostra, delimiters=",;\t")
    except csv.Error:
        return csv.excel


def _data(texto: str) -> datetime:
    from datetime import UTC

    for formato in ("%Y-%m-%d", "%d/%m/%Y", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M"):
        try:
            return datetime.strptime(texto, formato).replace(tzinfo=UTC)
        except ValueError:
            continue
    raise ValueError(f"data de validade não reconhecida: {texto!r}")


def _restringir_permissoes(caminho: Path) -> None:
    with suppress(OSError, NotImplementedError):
        os.chmod(caminho, 0o600)
