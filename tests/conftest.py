"""Configuração comum dos testes.

Os parâmetros do Argon2id ficam no mínimo aceitável em toda a suíte. Com os
padrões de produção, cada gravação custaria meio segundo e uma suíte com
algumas dezenas de casos passaria mais tempo derivando chave do que testando
qualquer coisa.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arca.crypto.kdf import MEMORIA_MINIMA_KIB, ParametrosKdf
from arca.crypto.segredo import ValorProtegido
from arca.model.armazenamento import Credenciais, OpcoesDeGravacao
from arca.model.cofre import Cofre, Entrada, Grupo

SENHA_DE_TESTE = "cofre-de-teste-92#"


@pytest.fixture
def kdf_rapido() -> ParametrosKdf:
    return ParametrosKdf(memoria_kib=MEMORIA_MINIMA_KIB, iteracoes=1, paralelismo=1)


@pytest.fixture
def opcoes(kdf_rapido: ParametrosKdf) -> OpcoesDeGravacao:
    return OpcoesDeGravacao(kdf=kdf_rapido)


@pytest.fixture
def credenciais() -> Credenciais:
    return Credenciais.a_partir_de(SENHA_DE_TESTE)


@pytest.fixture
def cofre() -> Cofre:
    """Cofre com alguma estrutura: dois grupos e três entradas."""
    vault = Cofre(raiz=Grupo(nome="Raiz"))
    bancos = vault.raiz.adicionar_grupo(Grupo(nome="Bancos"))
    internet = vault.raiz.adicionar_grupo(Grupo(nome="Internet"))

    bancos.adicionar_entrada(Entrada(
        titulo="Banco Exemplo",
        usuario="ana.silva",
        senha=ValorProtegido("K7#vLm2!qXz9"),
        url="https://banco.example",
    ))

    internet.adicionar_entrada(Entrada(
        titulo="Fórum",
        usuario="ana",
        senha=ValorProtegido("123456"),
        url="http://forum.example",
        notas="conta antiga",
    ))
    internet.adicionar_entrada(Entrada(
        titulo="Loja",
        usuario="ana@example.com",
        senha=ValorProtegido("123456"),
    ))
    return vault


@pytest.fixture
def caminho_cofre(tmp_path: Path) -> Path:
    return tmp_path / "teste.arca"
