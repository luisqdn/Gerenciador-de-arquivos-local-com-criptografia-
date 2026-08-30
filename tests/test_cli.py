"""Testes de ponta a ponta da linha de comando, incluindo importação e exportação."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from arca.cli.main import main
from arca.core.errors import ArcaError
from arca.core.model import Vault
from arca.core.vault_file import Credentials, SaveOptions, load
from arca.services import porting

from .conftest import SENHA_DE_TESTE

# Parâmetros mínimos: a suíte não deve gastar meio segundo por comando.
CUSTO_BAIXO = ["--memoria", "8", "--iteracoes", "1", "--threads", "1"]


@pytest.fixture
def cofre_cli(tmp_path: Path) -> Path:
    caminho = tmp_path / "cli.arca"
    assert main(["novo", str(caminho), "--senha-mestra", SENHA_DE_TESTE, *CUSTO_BAIXO]) == 0
    return caminho


def executar(*argumentos: str) -> int:
    return main(list(argumentos))


class TestCicloDeVida:
    def test_criar_e_inspecionar(self, cofre_cli: Path, capsys) -> None:
        assert executar("info", str(cofre_cli)) == 0
        saida = capsys.readouterr().out
        assert "AES-256" in saida
        assert "Argon2id" in saida

    def test_nao_sobrescreve_cofre_existente(self, cofre_cli: Path) -> None:
        assert executar("novo", str(cofre_cli), "--senha-mestra", "x", *CUSTO_BAIXO) == 1

    def test_cofre_inexistente(self, tmp_path: Path) -> None:
        assert executar("listar", str(tmp_path / "nao-existe.arca"),
                        "--senha-mestra", "x") == 1

    def test_senha_errada(self, cofre_cli: Path, capsys) -> None:
        assert executar("listar", str(cofre_cli), "--senha-mestra", "errada") == 1
        assert "incorret" in capsys.readouterr().err


class TestEntradas:
    def _adicionar(self, cofre: Path, titulo: str, **extras: str) -> int:
        argumentos = ["add", str(cofre), "--titulo", titulo,
                      "--senha-mestra", SENHA_DE_TESTE]
        for chave, valor in extras.items():
            argumentos += [f"--{chave.replace('_', '-')}", valor]
        return executar(*argumentos)

    def test_adicionar_com_senha_gerada(self, cofre_cli: Path) -> None:
        assert executar("add", str(cofre_cli), "--titulo", "Banco", "--usuario", "ana",
                        "--grupo", "Bancos", "--gerar", "24",
                        "--senha-mestra", SENHA_DE_TESTE) == 0
        aberto = load(cofre_cli, Credentials.from_inputs(SENHA_DE_TESTE))
        entrada = next(e for e in aberto.vault.entries() if e.title == "Banco")
        assert len(entrada.password) == 24
        assert entrada.path() == "Bancos/Banco"

    def test_listar_e_buscar(self, cofre_cli: Path, capsys) -> None:
        self._adicionar(cofre_cli, "Banco", usuario="ana", senha_nova="x")
        self._adicionar(cofre_cli, "Loja", usuario="bruno", senha_nova="y")

        assert executar("listar", str(cofre_cli), "--senha-mestra", SENHA_DE_TESTE) == 0
        assert "2 entrada(s)" in capsys.readouterr().out

        assert executar("buscar", str(cofre_cli), "usuario:bruno",
                        "--senha-mestra", SENHA_DE_TESTE) == 0
        saida = capsys.readouterr().out
        assert "Loja" in saida and "Banco" not in saida

    def test_ver_oculta_a_senha_por_padrao(self, cofre_cli: Path, capsys) -> None:
        self._adicionar(cofre_cli, "Banco", senha_nova="segredo-visivel")
        assert executar("ver", str(cofre_cli), "Banco",
                        "--senha-mestra", SENHA_DE_TESTE) == 0
        assert "segredo-visivel" not in capsys.readouterr().out

        assert executar("ver", str(cofre_cli), "Banco", "--revelar",
                        "--senha-mestra", SENHA_DE_TESTE) == 0
        assert "segredo-visivel" in capsys.readouterr().out

    def test_consulta_ambigua_e_recusada(self, cofre_cli: Path, capsys) -> None:
        self._adicionar(cofre_cli, "Banco Um", senha_nova="x")
        self._adicionar(cofre_cli, "Banco Dois", senha_nova="y")
        assert executar("ver", str(cofre_cli), "Banco",
                        "--senha-mestra", SENHA_DE_TESTE) == 1
        assert "refine a busca" in capsys.readouterr().err

    def test_editar_guarda_historico(self, cofre_cli: Path) -> None:
        self._adicionar(cofre_cli, "Banco", senha_nova="antiga")
        assert executar("editar", str(cofre_cli), "Banco", "--senha-nova", "nova",
                        "--senha-mestra", SENHA_DE_TESTE) == 0
        aberto = load(cofre_cli, Credentials.from_inputs(SENHA_DE_TESTE))
        entrada = next(aberto.vault.entries())
        assert entrada.password.reveal() == "nova"
        assert entrada.history[0].password.reveal() == "antiga"

    def test_editar_sem_opcoes(self, cofre_cli: Path) -> None:
        self._adicionar(cofre_cli, "Banco", senha_nova="x")
        assert executar("editar", str(cofre_cli), "Banco",
                        "--senha-mestra", SENHA_DE_TESTE) == 1

    def test_remover_manda_para_a_lixeira(self, cofre_cli: Path, capsys) -> None:
        self._adicionar(cofre_cli, "Banco", senha_nova="x")
        assert executar("remover", str(cofre_cli), "Banco", "--sim",
                        "--senha-mestra", SENHA_DE_TESTE) == 0
        aberto = load(cofre_cli, Credentials.from_inputs(SENHA_DE_TESTE))
        entrada = next(aberto.vault.entries())
        assert aberto.vault.is_in_recycle_bin(entrada)

        assert executar("lixeira", str(cofre_cli), "esvaziar",
                        "--senha-mestra", SENHA_DE_TESTE) == 0
        capsys.readouterr()
        aberto = load(cofre_cli, Credentials.from_inputs(SENHA_DE_TESTE))
        assert list(aberto.vault.entries()) == []

    def test_grupos(self, cofre_cli: Path) -> None:
        assert executar("grupo", str(cofre_cli), "Trabalho/Servidores",
                        "--senha-mestra", SENHA_DE_TESTE) == 0
        aberto = load(cofre_cli, Credentials.from_inputs(SENHA_DE_TESTE))
        assert aberto.vault.group_by_path("Trabalho/Servidores") is not None


class TestFerramentas:
    def test_gerar_senha(self, capsys) -> None:
        assert executar("gerar", "-n", "3", "-t", "16") == 0
        saida = capsys.readouterr().out
        linhas = [linha for linha in saida.splitlines() if linha.strip()]
        assert len(linhas) == 3
        assert all(len(linha) == 16 for linha in linhas)

    def test_gerar_frase(self, capsys) -> None:
        assert executar("gerar", "--frase", "--palavras", "6") == 0
        assert len(capsys.readouterr().out.strip().split("-")) == 6

    def test_perfil_desconhecido(self) -> None:
        # A validação é do próprio argparse, que encerra o processo com 2.
        with pytest.raises(SystemExit) as saida:
            executar("gerar", "--perfil", "inexistente")
        assert saida.value.code == 2

    def test_forca(self, capsys) -> None:
        assert executar("forca", "123456") == 0
        assert "muito fraca" in capsys.readouterr().out

    def test_auditar_devolve_codigo_de_erro_com_criticos(self, cofre_cli: Path,
                                                         capsys) -> None:
        executar("add", str(cofre_cli), "--titulo", "Fraca", "--senha-nova", "123456",
                 "--senha-mestra", SENHA_DE_TESTE)
        capsys.readouterr()
        assert executar("auditar", str(cofre_cli), "--senha-mestra", SENHA_DE_TESTE) == 1
        assert "Crítico" in capsys.readouterr().out


class TestCsv:
    def test_exportar_exige_confirmacao(self, cofre_cli: Path, tmp_path: Path) -> None:
        destino = tmp_path / "saida.csv"
        assert executar("exportar", str(cofre_cli), str(destino),
                        "--senha-mestra", SENHA_DE_TESTE) == 1
        assert not destino.exists()

    def test_ida_e_volta_por_csv(self, cofre_cli: Path, tmp_path: Path) -> None:
        executar("add", str(cofre_cli), "--titulo", "Banco", "--usuario", "ana",
                 "--grupo", "Bancos", "--senha-nova", "s3nh4", "--etiquetas", "a,b",
                 "--senha-mestra", SENHA_DE_TESTE)

        destino = tmp_path / "saida.csv"
        assert executar("exportar", str(cofre_cli), str(destino), "--confirmo",
                        "--senha-mestra", SENHA_DE_TESTE) == 0

        linhas = list(csv.DictReader(destino.open(encoding="utf-8")))
        assert linhas[0]["titulo"] == "Banco"
        assert linhas[0]["senha"] == "s3nh4"
        assert linhas[0]["grupo"] == "Bancos"

        outro = tmp_path / "destino.arca"
        executar("novo", str(outro), "--senha-mestra", SENHA_DE_TESTE, *CUSTO_BAIXO)
        assert executar("importar", str(outro), str(destino),
                        "--senha-mestra", SENHA_DE_TESTE) == 0

        aberto = load(outro, Credentials.from_inputs(SENHA_DE_TESTE))
        importada = next(e for e in aberto.vault.entries() if e.title == "Banco")
        assert importada.password.reveal() == "s3nh4"
        assert importada.tags == ["a", "b"]
        assert importada.path() == "Bancos/Banco"


class TestImportacaoDeTerceiros:
    def test_cabecalhos_em_ingles(self, tmp_path: Path) -> None:
        origem = tmp_path / "outro-gerenciador.csv"
        origem.write_text(
            "Group,Title,Username,Password,URL,Notes\n"
            "Trabalho,Servidor,root,r00t!,https://srv.example,acesso ssh\n",
            encoding="utf-8",
        )
        cofre = Vault.new("Destino")
        relatorio = porting.import_csv(cofre, origem)
        assert relatorio.imported == 1
        entrada = next(cofre.entries())
        assert entrada.title == "Servidor"
        assert entrada.password.reveal() == "r00t!"
        assert entrada.path() == "Trabalho/Servidor"

    def test_separador_ponto_e_virgula(self, tmp_path: Path) -> None:
        origem = tmp_path / "excel.csv"
        origem.write_text("titulo;usuario;senha\nLoja;ana;abc\n", encoding="utf-8")
        cofre = Vault.new("Destino")
        assert porting.import_csv(cofre, origem).imported == 1

    def test_bom_do_excel_nao_atrapalha(self, tmp_path: Path) -> None:
        origem = tmp_path / "bom.csv"
        origem.write_bytes("titulo,usuario,senha\nLoja,ana,abc\n".encode("utf-8-sig"))
        cofre = Vault.new("Destino")
        assert porting.import_csv(cofre, origem).imported == 1

    def test_linhas_sem_identificacao_sao_ignoradas(self, tmp_path: Path) -> None:
        origem = tmp_path / "parcial.csv"
        origem.write_text("titulo,usuario,senha\n,,abc\nLoja,ana,abc\n", encoding="utf-8")
        cofre = Vault.new("Destino")
        relatorio = porting.import_csv(cofre, origem)
        assert (relatorio.imported, relatorio.skipped) == (1, 1)

    def test_colunas_irreconheciveis(self, tmp_path: Path) -> None:
        origem = tmp_path / "estranho.csv"
        origem.write_text("coluna1,coluna2\na,b\n", encoding="utf-8")
        with pytest.raises(ArcaError):
            porting.import_csv(Vault.new("Destino"), origem)

    def test_exportacao_recusa_sem_confirmacao(self, tmp_path: Path) -> None:
        with pytest.raises(ArcaError):
            porting.export_csv(Vault.new("X"), tmp_path / "x.csv")

    def test_remocao_segura_apaga_o_arquivo(self, tmp_path: Path) -> None:
        alvo = tmp_path / "temporario.csv"
        alvo.write_text("senha em texto puro", encoding="utf-8")
        porting.secure_delete(alvo)
        assert not alvo.exists()


class TestOpcoesGlobais:
    def test_sem_subcomando_mostra_ajuda(self, capsys) -> None:
        assert main([]) == 2
        assert "comandos" in capsys.readouterr().out

    def test_chacha20_pela_linha_de_comando(self, tmp_path: Path) -> None:
        caminho = tmp_path / "chacha.arca"
        assert executar("novo", str(caminho), "--cifra", "chacha20",
                        "--senha-mestra", SENHA_DE_TESTE, *CUSTO_BAIXO) == 0
        from arca.core.ciphers import CipherId
        from arca.core.vault_file import inspect
        assert inspect(caminho).cipher is CipherId.CHACHA20

    def test_gravacao_preserva_os_parametros_do_cofre(self, tmp_path: Path) -> None:
        caminho = tmp_path / "params.arca"
        executar("novo", str(caminho), "--cifra", "chacha20", "--memoria", "16",
                 "--iteracoes", "3", "--threads", "2", "--senha-mestra", SENHA_DE_TESTE)
        executar("add", str(caminho), "--titulo", "X", "--senha-nova", "y",
                 "--senha-mestra", SENHA_DE_TESTE)

        from arca.core.ciphers import CipherId
        from arca.core.vault_file import inspect
        cabecalho = inspect(caminho)
        assert cabecalho.cipher is CipherId.CHACHA20
        assert cabecalho.kdf.memory_kib == 16 * 1024
        assert cabecalho.kdf.iterations == 3


def test_save_options_from_header_aceita_ajustes(cofre, caminho_cofre, credenciais,
                                                 opcoes) -> None:
    from arca.core import vault_file

    cabecalho = vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
    ajustadas = SaveOptions.from_header(cabecalho, make_backup=False)
    assert ajustadas.cipher is cabecalho.cipher
    assert ajustadas.kdf == cabecalho.kdf
    assert ajustadas.make_backup is False
