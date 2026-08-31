"""Busca sobre as entradas do cofre.

A sintaxe aceita filtros no formato `campo:valor` misturados a termos livres.
Termos livres batem em título, usuário, URL, notas e caminho do grupo;
filtros batem apenas no campo indicado. Tudo é conjuntivo: uma entrada só
entra no resultado se satisfizer todos os termos.

    banco                     -> qualquer campo textual contém "banco"
    usuario:ana url:gov.br    -> usuário contém "ana" e URL contém "gov.br"
    grupo:bancos fatura       -> está em "Bancos" e "fatura" em algum campo

Senhas não são pesquisáveis. Isso é intencional: permitir `senha:x` daria a
quem estiver de passagem pelo computador uma forma de confirmar palpites sem
nunca revelar a senha na tela.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from arca.model.vault import Entry, Vault

CAMPOS = {
    "titulo": "title",
    "título": "title",
    "usuario": "username",
    "usuário": "username",
    "url": "url",
    "notas": "notes",
    "nota": "notes",
    "grupo": "group",
}


@dataclass(slots=True)
class Query:
    terms: list[str] = field(default_factory=list)
    filters: list[tuple[str, str]] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.terms and not self.filters


def parse(texto: str) -> Query:
    consulta = Query()
    try:
        pedacos = shlex.split(texto)
    except ValueError:
        # Aspas desbalanceadas enquanto o usuário digita: trata como texto puro.
        pedacos = texto.split()

    for pedaco in pedacos:
        prefixo, separador, valor = pedaco.partition(":")
        campo = CAMPOS.get(prefixo.casefold()) if separador else None
        if campo is None or not valor:
            consulta.terms.append(pedaco.casefold())
        else:
            consulta.filters.append((campo, valor.casefold()))
    return consulta


def matches(entrada: Entry, consulta: Query) -> bool:
    if any(not _campo_contem(entrada, campo, valor) for campo, valor in consulta.filters):
        return False
    if not consulta.terms:
        return True
    alvo = _texto_pesquisavel(entrada)
    return all(termo in alvo for termo in consulta.terms)


def search(cofre: Vault, texto: str, incluir_lixeira: bool = False) -> list[Entry]:
    consulta = parse(texto)
    resultado = filter_entries(cofre.entries(), consulta)
    if incluir_lixeira:
        return list(resultado)
    return [e for e in resultado if not cofre.is_in_recycle_bin(e)]


def filter_entries(entradas: Iterable[Entry], consulta: Query) -> Iterator[Entry]:
    if consulta.is_empty:
        yield from entradas
        return
    for entrada in entradas:
        if matches(entrada, consulta):
            yield entrada


def _texto_pesquisavel(entrada: Entry) -> str:
    partes = [entrada.title, entrada.username, entrada.url, entrada.notes]
    if entrada.parent is not None:
        partes.append(entrada.parent.path())
    return " ".join(partes).casefold()


def _campo_contem(entrada: Entry, campo: str, valor: str) -> bool:
    if campo == "group":
        return entrada.parent is not None and valor in entrada.parent.path().casefold()
    return valor in str(getattr(entrada, campo, "")).casefold()
