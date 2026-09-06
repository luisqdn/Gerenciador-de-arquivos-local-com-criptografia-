"""Sessão de trabalho sobre um cofre.

A View não fala diretamente com `model.armazenamento`. Passa por aqui, e o motivo é
evitar que as regras de negócio -- quando marcar o cofre como sujo, o que
acontece ao trancar, que opções de gravação reaproveitar -- fiquem
espalhadas pelos widgets.

O controlador mantém as credenciais em memória enquanto o cofre está aberto,
porque cada gravação precisa refazer a derivação Argon2id com um sal novo.
Ao trancar, as credenciais e o modelo são descartados juntos.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from arca.crypto.segredo import ValorProtegido
from arca.model import armazenamento
from arca.model.armazenamento import Credenciais, OpcoesDeGravacao
from arca.model.cabecalho import Cabecalho
from arca.model.cofre import Cofre, Entrada, Grupo
from arca.model.erros import ErroArca, ErroCofreTrancado

Observador = Callable[[str], None]

EVENTO_ABERTO = "aberto"
EVENTO_FECHADO = "fechado"
EVENTO_SALVO = "salvo"
EVENTO_MODIFICADO = "modificado"


@dataclass(slots=True)
class SessionState:
    path: Path | None = None
    header: Cabecalho | None = None
    read_only: bool = False
    dirty: bool = False


class VaultController:
    def __init__(self) -> None:
        self._vault: Cofre | None = None
        self._credentials: Credenciais | None = None
        self._observadores: list[Observador] = []
        self.state = SessionState()

    # ------------------------------------------------------------------
    # Estado
    # ------------------------------------------------------------------

    @property
    def is_open(self) -> bool:
        return self._vault is not None

    @property
    def vault(self) -> Cofre:
        if self._vault is None:
            raise ErroCofreTrancado("nenhum cofre aberto")
        return self._vault

    @property
    def path(self) -> Path | None:
        return self.state.path

    @property
    def dirty(self) -> bool:
        return self.state.dirty

    @property
    def display_name(self) -> str:
        if self.state.path is not None:
            return self.state.path.stem
        return self._vault.metadados.nome if self._vault else ""

    def subscribe(self, observador: Observador) -> None:
        self._observadores.append(observador)

    def _emitir(self, evento: str) -> None:
        for observador in list(self._observadores):
            observador(evento)

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def create(self, caminho: Path, credenciais: Credenciais,
               opcoes: OpcoesDeGravacao | None = None, nome: str | None = None) -> None:
        if caminho.exists():
            raise ErroArca(f"já existe um arquivo em {caminho}")
        cofre = Cofre.novo(nome or caminho.stem)
        escolhas = opcoes or OpcoesDeGravacao()
        cabecalho = armazenamento.salvar(caminho, cofre, credenciais, escolhas)
        self._assumir(cofre, caminho, credenciais, cabecalho, somente_leitura=False)
        self._emitir(EVENTO_ABERTO)

    def open(self, caminho: Path, credenciais: Credenciais,
             somente_leitura: bool = False) -> None:
        aberto = armazenamento.carregar(caminho, credenciais)
        self._assumir(aberto.cofre, caminho, credenciais, aberto.cabecalho, somente_leitura)
        self._emitir(EVENTO_ABERTO)

    def save(self, opcoes: OpcoesDeGravacao | None = None) -> None:
        if self.state.read_only:
            raise ErroArca("cofre aberto somente para leitura")
        if self.state.path is None or self._credentials is None:
            raise ErroCofreTrancado("nenhum cofre aberto para salvar")
        escolhas = opcoes or self._opcoes_atuais()
        self.state.header = armazenamento.salvar(
            self.state.path, self.vault, self._credentials, escolhas
        )
        self.state.dirty = False
        self._emitir(EVENTO_SALVO)

    def save_as(self, caminho: Path, credenciais: Credenciais | None = None,
                opcoes: OpcoesDeGravacao | None = None) -> None:
        credenciais = credenciais or self._credentials
        if credenciais is None:
            raise ErroCofreTrancado("nenhum cofre aberto")
        escolhas = opcoes or self._opcoes_atuais()
        cabecalho = armazenamento.salvar(caminho, self.vault, credenciais, escolhas)
        self._credentials = credenciais
        self.state.path = caminho
        self.state.header = cabecalho
        self.state.read_only = False
        self.state.dirty = False
        self._emitir(EVENTO_SALVO)

    def change_credentials(self, novas: Credenciais,
                           opcoes: OpcoesDeGravacao | None = None) -> None:
        if not self.is_open or self.state.path is None:
            raise ErroCofreTrancado("nenhum cofre aberto")
        anteriores = self._credentials
        self._credentials = novas
        try:
            self.save(opcoes)
        except Exception:
            self._credentials = anteriores
            raise
        if anteriores is not None:
            anteriores.apagar()

    def close(self) -> None:
        """Tranca o cofre: descarta modelo e credenciais."""
        if self._credentials is not None:
            self._credentials.apagar()
            self._credentials = None
        self._vault = None
        self.state = SessionState()
        self._emitir(EVENTO_FECHADO)

    def _assumir(self, cofre: Cofre, caminho: Path, credenciais: Credenciais,
                 cabecalho: Cabecalho, somente_leitura: bool) -> None:
        if self.is_open:
            self.close()
        self._vault = cofre
        self._credentials = credenciais
        self.state = SessionState(
            path=caminho, header=cabecalho, read_only=somente_leitura, dirty=False
        )

    def _opcoes_atuais(self) -> OpcoesDeGravacao:
        if self.state.header is None:
            return OpcoesDeGravacao()
        return OpcoesDeGravacao.a_partir_do_cabecalho(self.state.header)

    # ------------------------------------------------------------------
    # Mutações
    # ------------------------------------------------------------------

    def mark_dirty(self) -> None:
        if not self.state.dirty:
            self.state.dirty = True
        self._emitir(EVENTO_MODIFICADO)

    def add_entry(self, grupo: Grupo, entrada: Entrada) -> Entrada:
        grupo.adicionar_entrada(entrada)
        self.mark_dirty()
        return entrada

    def update_entry(self, entrada: Entrada, alteracoes: dict[str, Any]) -> None:
        """Aplica alterações campo a campo.

        Se nada mudou de fato, não suja o cofre: abrir e fechar a janela de
        edição sem mexer em nada não deve marcar o arquivo como pendente.
        """
        if not self._alteracoes_efetivas(entrada, alteracoes):
            return
        for campo, valor in alteracoes.items():
            if campo == "senha":
                entrada.senha = ValorProtegido(valor)
            else:
                setattr(entrada, campo, valor)
        entrada.tempos.atualizar()
        self.mark_dirty()

    def delete_entry(self, entrada: Entrada, permanente: bool = False) -> None:
        self.vault.apagar_entrada(entrada, permanente=permanente)
        self.mark_dirty()

    def add_group(self, pai: Grupo, grupo: Grupo) -> Grupo:
        pai.adicionar_grupo(grupo)
        self.mark_dirty()
        return grupo

    def delete_group(self, grupo: Grupo, permanente: bool = False) -> None:
        self.vault.apagar_grupo(grupo, permanente=permanente)
        self.mark_dirty()

    def move_entry(self, entrada: Entrada, destino: Grupo) -> None:
        self.vault.mover_entrada(entrada, destino)
        self.mark_dirty()

    def move_group(self, grupo: Grupo, destino: Grupo) -> None:
        self.vault.mover_grupo(grupo, destino)
        self.mark_dirty()

    def empty_recycle_bin(self) -> int:
        removidos = self.vault.esvaziar_lixeira()
        if removidos:
            self.mark_dirty()
        return removidos

    @staticmethod
    def _alteracoes_efetivas(entrada: Entrada, alteracoes: dict[str, Any]) -> bool:
        for campo, novo in alteracoes.items():
            if campo == "senha":
                if entrada.senha.revelar() != novo:
                    return True
            elif getattr(entrada, campo, None) != novo:
                return True
        return False
