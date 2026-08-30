"""Subcomandos que operam sobre o arquivo de cofre como um todo."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from arca.cli import console, prompts
from arca.cli.context import cofre_aberto, grupo_alvo
from arca.core import vault_file
from arca.core.ciphers import CipherId
from arca.core.errors import ArcaError
from arca.core.header import Compression
from arca.core.kdf import KdfParameters, calibrate
from arca.core.vault_file import Credentials, SaveOptions
from arca.services import porting
from arca.services.vault_service import VaultService


def novo(args: Namespace) -> int:
    caminho = Path(args.cofre)
    if caminho.exists():
        raise ArcaError(f"já existe um arquivo em {caminho}")

    senha = args.senha or prompts.ler_senha_nova()

    parametros = _parametros_kdf(args)
    console.info(f"derivando a chave mestra ({parametros.describe()})...")
    opcoes = SaveOptions(
        cipher=CipherId[args.cifra.upper().replace("-", "_")],
        compression=Compression.NENHUMA if args.sem_compressao else Compression.GZIP,
        kdf=parametros,
    )

    servico = VaultService()
    servico.create(caminho, Credentials.from_inputs(senha),
                   opcoes, nome=args.nome or caminho.stem)
    servico.close()
    console.sucesso(f"cofre criado em {caminho}")
    return 0


def info(args: Namespace) -> int:
    caminho = Path(args.cofre)
    cabecalho = vault_file.inspect(caminho)

    console.secao(f"{caminho.name}")
    console.campo("formato", f"Arca {cabecalho.version[0]}.{cabecalho.version[1]}")
    console.campo("cifra", cabecalho.cipher.rotulo)
    console.campo("compressão", "gzip" if cabecalho.compression else "nenhuma")
    console.campo("kdf", cabecalho.kdf.describe())
    console.campo("tamanho", f"{caminho.stat().st_size} bytes")

    if not args.conteudo:
        console.info("")
        console.info("use --conteudo para abrir o cofre e ver as estatísticas internas")
        return 0

    with cofre_aberto(args) as servico:
        numeros = servico.vault.stats()
        meta = servico.vault.metadata
        console.secao("Conteúdo")
        console.campo("nome", meta.name)
        console.campo("grupos", str(numeros["grupos"]))
        console.campo("entradas", str(numeros["entradas"]))
        console.campo("vencidas", str(numeros["expiradas"]))
        console.campo("na lixeira", str(numeros["na_lixeira"]))
        console.campo("criado em", meta.created.date().isoformat())
        if meta.last_saved:
            console.campo("salvo em", meta.last_saved.isoformat(sep=" ", timespec="seconds"))
    return 0


def senha(args: Namespace) -> int:
    """Troca a senha mestra de um cofre existente."""
    with cofre_aberto(args, somente_leitura=False) as servico:
        nova_senha = prompts.ler_senha_nova()

        opcoes = None
        if args.recalibrar:
            parametros = calibrate(args.alvo)
            console.info(f"novos parâmetros: {parametros.describe()}")
            opcoes = SaveOptions.from_header(servico.state.header, kdf=parametros)

        servico.change_credentials(Credentials.from_inputs(nova_senha), opcoes)
        console.sucesso("senha mestra atualizada")
    return 0


def exportar(args: Namespace) -> int:
    destino = Path(args.destino)
    if not args.confirmo:
        raise ArcaError(
            "a exportação grava todas as senhas em texto puro. "
            "Repita o comando com --confirmo se for isso mesmo."
        )
    with cofre_aberto(args) as servico:
        total = porting.export_csv(servico.vault, destino, confirmado=True,
                                   incluir_lixeira=args.incluir_lixeira)
    console.sucesso(f"{total} entrada(s) exportada(s) para {destino}")
    console.aviso("apague o arquivo assim que terminar de usá-lo")
    return 0


def importar(args: Namespace) -> int:
    origem = Path(args.origem)
    if not origem.exists():
        raise ArcaError(f"arquivo não encontrado: {origem}")
    with cofre_aberto(args, somente_leitura=False) as servico:
        destino = grupo_alvo(servico, args.grupo)
        relatorio = porting.import_csv(servico.vault, origem, destino,
                                       usar_coluna_grupo=not args.grupo)
        for problema in relatorio.problems[:10]:
            console.aviso(problema)
        if relatorio.imported:
            servico.mark_dirty()
            servico.save()
        console.sucesso(relatorio.summary())
    return 0


def _parametros_kdf(args: Namespace) -> KdfParameters:
    if args.calibrar:
        console.info("medindo o custo do Argon2id nesta máquina...")
        return calibrate(args.alvo)
    return KdfParameters(
        memory_kib=args.memoria * 1024,
        iterations=args.iteracoes,
        parallelism=args.threads,
    )
