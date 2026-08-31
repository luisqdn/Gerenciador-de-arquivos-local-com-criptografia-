"""Configuração comum dos testes.

Os parâmetros do Argon2id ficam no mínimo aceitável em toda a suíte. Com os
padrões de produção, cada gravação custaria meio segundo e uma suíte com
algumas dezenas de casos passaria mais tempo derivando chave do que testando
qualquer coisa.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arca.crypto.kdf import MEMORIA_MINIMA_KIB, KdfParameters
from arca.crypto.secret import ProtectedValue
from arca.model.storage import Credentials, SaveOptions
from arca.model.vault import Entry, Group, Vault

SENHA_DE_TESTE = "cofre-de-teste-92#"


@pytest.fixture
def kdf_rapido() -> KdfParameters:
    return KdfParameters(memory_kib=MEMORIA_MINIMA_KIB, iterations=1, parallelism=1)


@pytest.fixture
def opcoes(kdf_rapido: KdfParameters) -> SaveOptions:
    return SaveOptions(kdf=kdf_rapido)


@pytest.fixture
def credenciais() -> Credentials:
    return Credentials.from_inputs(SENHA_DE_TESTE)


@pytest.fixture
def cofre() -> Vault:
    """Cofre com alguma estrutura: dois grupos e três entradas."""
    vault = Vault(root=Group(name="Raiz"))
    bancos = vault.root.add_group(Group(name="Bancos"))
    internet = vault.root.add_group(Group(name="Internet"))

    bancos.add_entry(Entry(
        title="Banco Exemplo",
        username="ana.silva",
        password=ProtectedValue("K7#vLm2!qXz9"),
        url="https://banco.example",
    ))

    internet.add_entry(Entry(
        title="Fórum",
        username="ana",
        password=ProtectedValue("123456"),
        url="http://forum.example",
        notes="conta antiga",
    ))
    internet.add_entry(Entry(
        title="Loja",
        username="ana@example.com",
        password=ProtectedValue("123456"),
    ))
    return vault


@pytest.fixture
def caminho_cofre(tmp_path: Path) -> Path:
    return tmp_path / "teste.arca"
