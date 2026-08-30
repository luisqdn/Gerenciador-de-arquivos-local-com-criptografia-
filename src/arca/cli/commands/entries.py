"""Subcomandos que operam sobre grupos e entradas."""

from __future__ import annotations

import time
from argparse import Namespace
from datetime import UTC, datetime

from arca.cli import clipboard, console, prompts
from arca.cli.context import cofre_aberto, entrada_unica, grupo_alvo
from arca.core import search
from arca.core.errors import ArcaError
from arca.core.generator import PasswordRecipe, generate_password
from arca.core.model import Entry, Group
from arca.core.secret import ProtectedValue
from arca.core.strength import evaluate

SEGUNDOS_PADRAO_LIMPEZA = 20


def listar(args: Namespace) -> int:
    with cofre_aberto(args) as servico:
        cofre = servico.vault
        if args.arvore:
            console.arvore(cofre.root.name, _ramos(cofre.root))
            return 0

        raiz = grupo_alvo(servico, args.grupo, criar=False) if args.grupo else cofre.root
        entradas = [
            e for e in raiz.all_entries()
            if args.incluir_lixeira or not cofre.is_in_recycle_bin(e)
        ]
        entradas.sort(key=lambda e: (e.parent.path() if e.parent else "", e.title.casefold()))
        console.tabela(
            ["grupo", "título", "usuário", "url", "modificada"],
            [_linha(e) for e in entradas],
        )
        console.info("")
        console.info(console.colorir(f"{len(entradas)} entrada(s)", "cinza"))
    return 0


def buscar(args: Namespace) -> int:
    with cofre_aberto(args) as servico:
        encontradas = search.search(servico.vault, args.consulta,
                                    incluir_lixeira=args.incluir_lixeira)
        console.tabela(
            ["grupo", "título", "usuário", "url", "modificada"],
            [_linha(e) for e in encontradas],
        )
        console.info("")
        console.info(console.colorir(f"{len(encontradas)} resultado(s)", "cinza"))
    return 0


def ver(args: Namespace) -> int:
    with cofre_aberto(args) as servico:
        entrada = entrada_unica(servico, args.consulta)
        _mostrar(entrada, revelar=args.revelar)

        if args.copiar:
            clipboard.copiar(entrada.password.reveal())
            console.sucesso("senha copiada para a área de transferência")
            _limpar_depois(args.limpar)
    return 0


def add(args: Namespace) -> int:
    with cofre_aberto(args, somente_leitura=False) as servico:
        senha = _resolver_senha(args, servico.vault.metadata.name)
        entrada = Entry(
            title=args.titulo,
            username=args.usuario or servico.vault.metadata.default_username,
            password=ProtectedValue(senha),
            url=args.url or "",
            notes=args.notas or "",
            tags=_etiquetas(args.etiquetas),
        )
        if args.expira_em:
            entrada.times.expires_at = _data(args.expira_em)

        destino = grupo_alvo(servico, args.grupo)
        servico.add_entry(destino, entrada)
        servico.save()

        console.sucesso(f"entrada criada em {entrada.path()}")
        if args.gerar and not args.mostrar:
            console.info("use `arca ver` com --revelar para exibi-la")
        if args.mostrar:
            console.campo("senha", senha)
    return 0


def editar(args: Namespace) -> int:
    with cofre_aberto(args, somente_leitura=False) as servico:
        entrada = entrada_unica(servico, args.consulta)
        alteracoes: dict[str, object] = {}

        for opcao, campo in (("titulo", "title"), ("usuario", "username"),
                             ("url", "url"), ("notas", "notes")):
            valor = getattr(args, opcao)
            if valor is not None:
                alteracoes[campo] = valor
        if args.etiquetas is not None:
            alteracoes["tags"] = _etiquetas(args.etiquetas)
        if args.expira_em is not None:
            alteracoes["expires_at"] = _data(args.expira_em) if args.expira_em else None
        if args.gerar or args.senha_nova or args.perguntar_senha:
            alteracoes["password"] = _resolver_senha(args, entrada.display_title, editando=True)

        if not alteracoes and not args.mover_para:
            raise ArcaError("nada a alterar; informe ao menos uma opção")

        servico.update_entry(entrada, alteracoes)
        if args.mover_para:
            servico.move_entry(entrada, grupo_alvo(servico, args.mover_para))

        if not servico.dirty:
            console.info("os valores informados já eram os atuais; nada foi alterado")
            return 0
        servico.save()
        console.sucesso(f"entrada atualizada ({entrada.path()})")
    return 0


def remover(args: Namespace) -> int:
    with cofre_aberto(args, somente_leitura=False) as servico:
        entrada = entrada_unica(servico, args.consulta)
        destino = "definitivamente" if args.permanente else "para a lixeira"
        if not args.sim and not prompts.confirmar(f"Remover {entrada.path()!r} {destino}?"):
            console.info("cancelado")
            return 1
        servico.delete_entry(entrada, permanente=args.permanente)
        servico.save()
        console.sucesso(f"entrada removida {destino}")
    return 0


def grupo(args: Namespace) -> int:
    with cofre_aberto(args, somente_leitura=False) as servico:
        if args.remover:
            alvo = grupo_alvo(servico, args.caminho, criar=False)
            if not args.sim and not prompts.confirmar(
                f"Remover o grupo {alvo.path()!r} e todo o seu conteúdo?"
            ):
                console.info("cancelado")
                return 1
            servico.delete_group(alvo, permanente=args.permanente)
            console.sucesso("grupo removido")
        else:
            criado = servico.vault.group_by_path(args.caminho, criar=True)
            if criado is None:
                raise ArcaError(f"não foi possível criar {args.caminho}")
            servico.mark_dirty()
            console.sucesso(f"grupo disponível em {criado.path() or '/'}")
        servico.save()
    return 0


def lixeira(args: Namespace) -> int:
    with cofre_aberto(args, somente_leitura=args.acao != "esvaziar") as servico:
        deposito = servico.vault.recycle_bin(criar=False)
        if deposito is None:
            console.info("a lixeira está vazia")
            return 0
        if args.acao == "listar":
            console.tabela(
                ["título", "usuário", "removida em"],
                [(e.display_title, e.username,
                  e.times.modified.date().isoformat()) for e in deposito.all_entries()],
            )
            return 0
        removidos = servico.empty_recycle_bin()
        servico.save()
        console.sucesso(f"{removidos} entrada(s) apagada(s) definitivamente")
    return 0


# --------------------------------------------------------------------------
# Auxiliares
# --------------------------------------------------------------------------

def _mostrar(entrada: Entry, revelar: bool) -> None:
    console.secao(entrada.display_title)
    console.campo("grupo", entrada.parent.path() if entrada.parent else "")
    console.campo("usuário", entrada.username)
    console.campo("senha", entrada.password.reveal() if revelar else "•" * len(entrada.password))
    console.campo("url", entrada.url)
    if entrada.tags:
        console.campo("etiquetas", ", ".join(entrada.tags))
    if entrada.notes:
        console.campo("notas", entrada.notes.replace("\n", "\n" + " " * 15))

    avaliacao = evaluate(entrada.password.reveal())
    console.campo("força", f"{prompts.nivel_colorido(avaliacao.level)} ({avaliacao.bits:.0f} bits)")

    console.campo("criada em", entrada.times.created.date().isoformat())
    console.campo("modificada", entrada.times.modified.date().isoformat())
    if entrada.times.expires_at:
        estado = " (vencida)" if entrada.times.expired else ""
        console.campo("expira em", entrada.times.expires_at.date().isoformat() + estado)
    if entrada.history:
        console.campo("histórico", f"{len(entrada.history)} versão(ões) anterior(es)")

    for campo in entrada.fields:
        valor = campo.value.reveal() if (revelar or not campo.protected) else "•" * 8
        console.campo(campo.name, valor)


def _linha(entrada: Entry) -> tuple[str, ...]:
    marca = " (vencida)" if entrada.times.expired else ""
    return (
        entrada.parent.path() if entrada.parent else "",
        entrada.display_title + marca,
        entrada.username,
        entrada.url[:40],
        entrada.times.modified.date().isoformat(),
    )


def _ramos(grupo_atual: Group) -> list[tuple[str, list]]:
    ramos: list[tuple[str, list]] = []
    for filho in grupo_atual.groups:
        quantidade = len(filho.entries)
        rotulo = f"{filho.name} ({quantidade})" if quantidade else filho.name
        ramos.append((rotulo, _ramos(filho)))
    for entrada in grupo_atual.entries:
        ramos.append((console.colorir(entrada.display_title, "cinza"), []))
    return ramos


def _resolver_senha(args: Namespace, rotulo: str, editando: bool = False) -> str:
    if getattr(args, "gerar", 0):
        receita = PasswordRecipe(length=args.gerar)
        return generate_password(receita)
    valor = getattr(args, "senha_nova", None)
    if valor:
        return valor
    return prompts.ler_senha_nova(f"Senha para {rotulo}", minimo_bits=0 if editando else 40)


def _etiquetas(bruto: str | None) -> list[str]:
    if not bruto:
        return []
    return [t.strip() for t in bruto.split(",") if t.strip()]


def _data(texto: str) -> datetime:
    try:
        return datetime.fromisoformat(texto).replace(tzinfo=UTC)
    except ValueError as exc:
        raise ArcaError(f"data inválida: {texto!r} (use AAAA-MM-DD)") from exc


def _limpar_depois(segundos: int) -> None:
    if segundos <= 0:
        console.aviso("a senha permanece na área de transferência até ser sobrescrita")
        return
    console.info(f"limpando a área de transferência em {segundos}s (Ctrl+C cancela a espera)")
    try:
        time.sleep(segundos)
    except KeyboardInterrupt:
        console.info("")
    clipboard.limpar()
    console.sucesso("área de transferência limpa")
