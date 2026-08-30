"""Ponte entre os argumentos da linha de comando e a camada de serviço.

Cada execução da CLI abre o cofre, faz uma coisa e sai -- não há sessão
persistente, e portanto não há processo residente guardando a chave em
memória. O preço é uma derivação Argon2id por comando; o ganho é que fechar o
terminal já é suficiente para trancar tudo.
"""

from __future__ import annotations

from argparse import Namespace
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from arca.cli import console, prompts
from arca.core import search
from arca.core.errors import ArcaError
from arca.core.model import Entry, Group
from arca.services.vault_service import VaultService


@contextmanager
def cofre_aberto(args: Namespace, somente_leitura: bool = True) -> Iterator[VaultService]:
    """Abre o cofre indicado nos argumentos e garante o fechamento no final."""
    caminho = Path(args.cofre)
    if not caminho.exists():
        raise ArcaError(f"cofre não encontrado: {caminho}")

    credenciais = prompts.montar_credenciais(senha=getattr(args, "senha", None))
    servico = VaultService()
    servico.open(caminho, credenciais, somente_leitura=somente_leitura,
                 forcar_trava=getattr(args, "forcar", False))
    try:
        yield servico
    finally:
        servico.close()


def entrada_unica(servico: VaultService, consulta: str) -> Entry:
    """Resolve uma consulta em exatamente uma entrada, ou explica a ambiguidade."""
    encontradas = search.search(servico.vault, consulta)
    if not encontradas:
        raise ArcaError(f"nenhuma entrada corresponde a {consulta!r}")
    if len(encontradas) > 1:
        console.aviso(f"{len(encontradas)} entradas correspondem a {consulta!r}:")
        console.tabela(
            ["grupo", "título", "usuário"],
            [(e.parent.path() if e.parent else "", e.display_title, e.username)
             for e in encontradas[:10]],
        )
        raise ArcaError("refine a busca até que reste uma única entrada")
    return encontradas[0]


def grupo_alvo(servico: VaultService, caminho: str | None, criar: bool = True) -> Group:
    if not caminho:
        return servico.vault.root
    grupo = servico.vault.group_by_path(caminho, criar=criar)
    if grupo is None:
        raise ArcaError(f"grupo não encontrado: {caminho}")
    return grupo


def salvar(servico: VaultService, mensagem: str) -> None:
    servico.save()
    console.sucesso(mensagem)
