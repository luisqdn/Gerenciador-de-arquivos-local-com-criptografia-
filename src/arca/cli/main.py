"""Ponto de entrada da linha de comando.

O parser fica todo neste arquivo, e não espalhado pelos módulos de comando,
porque a ajuda do programa é um documento em si: ler `_construir_parser` de
cima a baixo deve bastar para saber tudo o que o Arca faz pelo terminal.
"""

from __future__ import annotations

import argparse
import sys

from arca import APP_NAME, APP_VERSION
from arca.cli import console
from arca.cli.commands import entries, tools, vault
from arca.core.errors import ArcaError

DESCRICAO = f"{APP_NAME} - gerenciador de senhas local com cofre criptografado."

EPILOGO = """exemplos:
  arca novo pessoal.arca --calibrar
  arca add pessoal.arca --titulo "Banco" --usuario ana --grupo Bancos --gerar 24
  arca buscar pessoal.arca "usuario:ana"
  arca ver pessoal.arca banco --copiar
  arca auditar pessoal.arca
  arca gerar --frase --palavras 6
"""


def main(argv: list[str] | None = None) -> int:
    parser = _construir_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "funcao", None):
        parser.print_help()
        return 2

    try:
        return args.funcao(args)
    except ArcaError as exc:
        console.erro(str(exc))
        return 1
    except KeyboardInterrupt:
        console.info("")
        console.erro("interrompido")
        return 130
    except BrokenPipeError:
        return 0


def _construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arca",
        description=DESCRICAO,
        epilog=EPILOGO,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--versao", action="version", version=f"{APP_NAME} {APP_VERSION}")
    sub = parser.add_subparsers(title="comandos", metavar="<comando>")

    _comando_novo(sub)
    _comando_info(sub)
    _comando_listar(sub)
    _comando_buscar(sub)
    _comando_ver(sub)
    _comando_add(sub)
    _comando_editar(sub)
    _comando_remover(sub)
    _comando_grupo(sub)
    _comando_lixeira(sub)
    _comando_auditar(sub)
    _comando_senha(sub)
    _comando_exportar(sub)
    _comando_importar(sub)
    _comando_gerar(sub)
    _comando_forca(sub)
    _comando_medir(sub)
    return parser


# --------------------------------------------------------------------------
# Blocos reaproveitados
# --------------------------------------------------------------------------

def _credenciais(parser: argparse.ArgumentParser) -> None:
    grupo = parser.add_argument_group("autenticação")
    # Aceita a senha mestra como argumento para uso em scripts e testes. Fica
    # fora da ajuda de propósito: a linha de comando aparece na lista de
    # processos e costuma ir parar no histórico do shell.
    grupo.add_argument("--senha-mestra", dest="senha", metavar="TEXTO",
                       help=argparse.SUPPRESS)
    grupo.add_argument("--forcar", action="store_true",
                       help="ignorar a trava deixada por outro processo")


def _com_cofre(sub, nome: str, ajuda: str) -> argparse.ArgumentParser:
    parser = sub.add_parser(nome, help=ajuda, description=ajuda)
    parser.add_argument("cofre", help="caminho do arquivo .arca")
    _credenciais(parser)
    return parser


# --------------------------------------------------------------------------
# Comandos
# --------------------------------------------------------------------------

def _comando_novo(sub) -> None:
    p = sub.add_parser("novo", help="cria um cofre vazio",
                       description="Cria um cofre novo e define a senha mestra.")
    p.add_argument("cofre", help="caminho do arquivo .arca a criar")
    p.add_argument("--nome", help="nome do cofre (padrão: nome do arquivo)")
    p.add_argument("--cifra", choices=["aes256-cbc", "chacha20"], default="aes256-cbc",
                   help="suíte de cifragem do corpo (padrão: aes256-cbc)")
    p.add_argument("--sem-compressao", action="store_true",
                   help="não comprimir o payload antes de cifrar")

    custo = p.add_argument_group("custo do Argon2id")
    custo.add_argument("--calibrar", action="store_true",
                       help="medir a máquina e escolher as iterações automaticamente")
    custo.add_argument("--alvo", type=float, default=0.6, metavar="SEGUNDOS",
                       help="tempo alvo de derivação ao calibrar (padrão: 0,6 s)")
    custo.add_argument("--memoria", type=int, default=64, metavar="MIB",
                       help="memória em MiB (padrão: 64)")
    custo.add_argument("--iteracoes", type=int, default=4, help="iterações (padrão: 4)")
    custo.add_argument("--threads", type=int, default=4, help="paralelismo (padrão: 4)")

    autenticacao = p.add_argument_group("autenticação")
    autenticacao.add_argument("--senha-mestra", dest="senha", metavar="TEXTO",
                              help=argparse.SUPPRESS)
    p.set_defaults(funcao=vault.novo)


def _comando_info(sub) -> None:
    p = _com_cofre(sub, "info", "mostra os parâmetros criptográficos do cofre")
    p.add_argument("--conteudo", action="store_true",
                   help="abrir o cofre e mostrar também as estatísticas internas")
    p.set_defaults(funcao=vault.info)


def _comando_listar(sub) -> None:
    p = _com_cofre(sub, "listar", "lista as entradas do cofre")
    p.add_argument("-g", "--grupo", help="restringir a um grupo (ex.: Bancos/Cartões)")
    p.add_argument("--arvore", action="store_true", help="mostrar a hierarquia completa")
    p.add_argument("--incluir-lixeira", action="store_true")
    p.set_defaults(funcao=entries.listar)


def _comando_buscar(sub) -> None:
    p = _com_cofre(sub, "buscar", "procura entradas por texto ou filtros")
    p.add_argument("consulta", help='ex.: "banco", "usuario:ana url:gov.br", "expirada:sim"')
    p.add_argument("--incluir-lixeira", action="store_true")
    p.set_defaults(funcao=entries.buscar)


def _comando_ver(sub) -> None:
    p = _com_cofre(sub, "ver", "exibe uma entrada")
    p.add_argument("consulta", help="texto que identifique uma única entrada")
    p.add_argument("--revelar", action="store_true", help="exibir a senha na tela")
    p.add_argument("--copiar", action="store_true",
                   help="copiar a senha para a área de transferência")
    p.add_argument("--limpar", type=int, default=entries.SEGUNDOS_PADRAO_LIMPEZA,
                   metavar="SEGUNDOS",
                   help="apagar a área de transferência depois deste tempo (0 desliga)")
    p.set_defaults(funcao=entries.ver)


def _comando_add(sub) -> None:
    p = _com_cofre(sub, "add", "cria uma entrada")
    p.add_argument("--titulo", required=True)
    p.add_argument("--usuario")
    p.add_argument("--url")
    p.add_argument("--notas")
    p.add_argument("--etiquetas", metavar="A,B,C")
    p.add_argument("-g", "--grupo", help="grupo de destino; criado se não existir")
    p.add_argument("--expira-em", metavar="AAAA-MM-DD")
    p.add_argument("--gerar", type=int, nargs="?", const=20, default=0, metavar="TAMANHO",
                   help="gerar a senha em vez de pedir (padrão: 20 caracteres)")
    p.add_argument("--senha-nova", metavar="TEXTO", help=argparse.SUPPRESS)
    p.add_argument("--mostrar", action="store_true", help="exibir a senha gerada na tela")
    p.set_defaults(funcao=entries.add)


def _comando_editar(sub) -> None:
    p = _com_cofre(sub, "editar", "altera uma entrada existente")
    p.add_argument("consulta")
    p.add_argument("--titulo")
    p.add_argument("--usuario")
    p.add_argument("--url")
    p.add_argument("--notas")
    p.add_argument("--etiquetas", metavar="A,B,C")
    p.add_argument("--expira-em", metavar="AAAA-MM-DD",
                   help="vazio para remover a data de validade")
    p.add_argument("--mover-para", metavar="GRUPO")
    p.add_argument("--gerar", type=int, nargs="?", const=20, default=0, metavar="TAMANHO",
                   help="substituir a senha por uma gerada")
    p.add_argument("--perguntar-senha", action="store_true", help="digitar uma senha nova")
    p.add_argument("--senha-nova", metavar="TEXTO", help=argparse.SUPPRESS)
    p.set_defaults(funcao=entries.editar)


def _comando_remover(sub) -> None:
    p = _com_cofre(sub, "remover", "manda uma entrada para a lixeira")
    p.add_argument("consulta")
    p.add_argument("--permanente", action="store_true", help="apagar sem passar pela lixeira")
    p.add_argument("-s", "--sim", action="store_true", help="não pedir confirmação")
    p.set_defaults(funcao=entries.remover)


def _comando_grupo(sub) -> None:
    p = _com_cofre(sub, "grupo", "cria ou remove grupos")
    p.add_argument("caminho", help="ex.: Bancos/Cartões")
    p.add_argument("--remover", action="store_true")
    p.add_argument("--permanente", action="store_true")
    p.add_argument("-s", "--sim", action="store_true")
    p.set_defaults(funcao=entries.grupo)


def _comando_lixeira(sub) -> None:
    p = _com_cofre(sub, "lixeira", "lista ou esvazia a lixeira")
    p.add_argument("acao", choices=["listar", "esvaziar"], nargs="?", default="listar")
    p.set_defaults(funcao=entries.lixeira)


def _comando_auditar(sub) -> None:
    p = _com_cofre(sub, "auditar", "procura senhas fracas, repetidas ou vencidas")
    p.add_argument("--tudo", action="store_true", help="incluir os avisos informativos")
    p.set_defaults(funcao=tools.auditar)


def _comando_senha(sub) -> None:
    p = _com_cofre(sub, "senha", "troca a senha mestra do cofre")
    p.add_argument("--recalibrar", action="store_true",
                   help="ajustar os parâmetros do Argon2id a esta máquina")
    p.add_argument("--alvo", type=float, default=0.6, metavar="SEGUNDOS")
    p.set_defaults(funcao=vault.senha)


def _comando_exportar(sub) -> None:
    p = _com_cofre(sub, "exportar", "grava as entradas em CSV sem proteção")
    p.add_argument("destino", help="arquivo .csv a criar")
    p.add_argument("--confirmo", action="store_true",
                   help="confirma que as senhas ficarão em texto puro")
    p.add_argument("--incluir-lixeira", action="store_true")
    p.set_defaults(funcao=vault.exportar)


def _comando_importar(sub) -> None:
    p = _com_cofre(sub, "importar", "traz entradas de um arquivo CSV")
    p.add_argument("origem", help="arquivo .csv de origem")
    p.add_argument("-g", "--grupo", help="colocar tudo neste grupo, ignorando a coluna de grupo")
    p.set_defaults(funcao=vault.importar)


def _comando_gerar(sub) -> None:
    p = sub.add_parser("gerar", help="gera senhas ou frases-senha",
                       description="Gera segredos com o gerador criptográfico do sistema.")
    p.add_argument("-n", "--quantidade", type=int, default=1)
    p.add_argument("-t", "--tamanho", type=int, help="comprimento da senha (padrão: 20)")
    p.add_argument("--perfil", choices=sorted(tools.PERFIS), help="conjunto pronto de opções")
    p.add_argument("--copiar", action="store_true")

    conjuntos = p.add_argument_group("conjuntos de caracteres")
    conjuntos.add_argument("--sem-minusculas", action="store_true")
    conjuntos.add_argument("--sem-maiusculas", action="store_true")
    conjuntos.add_argument("--sem-digitos", action="store_true")
    conjuntos.add_argument("--sem-simbolos", action="store_true")
    conjuntos.add_argument("--sem-ambiguos", action="store_true",
                           help="excluir caracteres confundíveis (0/O, 1/l/I, ...)")
    conjuntos.add_argument("--excluir", metavar="CARACTERES")

    frase = p.add_argument_group("frases-senha")
    frase.add_argument("--frase", action="store_true", help="gerar uma frase-senha")
    frase.add_argument("--palavras", type=int, default=5)
    frase.add_argument("--separador", default="-")
    frase.add_argument("--maiusculas", action="store_true",
                       help="iniciar cada palavra em maiúscula")
    frase.add_argument("--digitos", type=int, default=0, help="acrescentar N dígitos ao final")
    frase.add_argument("--lista", metavar="ARQUIVO", help="usar outra lista de palavras")
    frase.add_argument("--pin", action="store_true", help="gerar apenas dígitos")
    p.set_defaults(funcao=tools.gerar)


def _comando_forca(sub) -> None:
    p = sub.add_parser("forca", help="avalia a força de uma senha",
                       description="Estima a entropia de uma senha, sem enviá-la a lugar nenhum.")
    p.add_argument("senha", nargs="?", help="se omitida, é lida sem eco no terminal")
    p.set_defaults(funcao=tools.forca)


def _comando_medir(sub) -> None:
    p = sub.add_parser("medir", help="mede o custo do Argon2id nesta máquina",
                       description="Ajuda a escolher os parâmetros do KDF.")
    p.add_argument("--memorias", type=int, nargs="+", default=[32, 64, 128], metavar="MIB")
    p.add_argument("--iteracoes", type=int, nargs="+", default=[2, 4, 8])
    p.add_argument("--threads", type=int, default=4)
    p.set_defaults(funcao=tools.medir)


if __name__ == "__main__":
    sys.exit(main())
