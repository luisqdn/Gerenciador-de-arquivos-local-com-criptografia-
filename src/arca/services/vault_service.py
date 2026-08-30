"""Sessão de trabalho sobre um cofre.

A GUI e a CLI não falam diretamente com `core.vault_file`. Elas passam por
aqui, e o motivo é evitar que as regras de negócio -- quando empilhar
histórico, quando marcar o cofre como sujo, quando tomar a trava do arquivo,
o que acontece ao trancar -- fiquem duplicadas em duas interfaces que
inevitavelmente divergiriam.

O serviço mantém as credenciais em memória enquanto o cofre está aberto,
porque cada gravação precisa refazer a derivação Argon2id com um sal novo.
Ao trancar, as credenciais e o modelo são descartados juntos.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from arca.core import vault_file
from arca.core.errors import ArcaError, VaultLockedError
from arca.core.header import VaultHeader
from arca.core.model import Entry, Group, Vault
from arca.core.secret import ProtectedValue
from arca.core.vault_file import Credentials, SaveOptions
from arca.services.filelock import VaultLock

Observador = Callable[[str], None]

EVENTO_ABERTO = "aberto"
EVENTO_FECHADO = "fechado"
EVENTO_SALVO = "salvo"
EVENTO_MODIFICADO = "modificado"


@dataclass(slots=True)
class SessionState:
    path: Path | None = None
    header: VaultHeader | None = None
    read_only: bool = False
    dirty: bool = False


class VaultService:
    def __init__(self) -> None:
        self._vault: Vault | None = None
        self._credentials: Credentials | None = None
        self._lock: VaultLock | None = None
        self._observadores: list[Observador] = []
        self.state = SessionState()

    # ------------------------------------------------------------------
    # Estado
    # ------------------------------------------------------------------

    @property
    def is_open(self) -> bool:
        return self._vault is not None

    @property
    def vault(self) -> Vault:
        if self._vault is None:
            raise VaultLockedError("nenhum cofre aberto")
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
        return self._vault.metadata.name if self._vault else ""

    def subscribe(self, observador: Observador) -> None:
        self._observadores.append(observador)

    def _emitir(self, evento: str) -> None:
        for observador in list(self._observadores):
            observador(evento)

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def create(self, caminho: Path, credenciais: Credentials,
               opcoes: SaveOptions | None = None, nome: str | None = None) -> None:
        if caminho.exists():
            raise ArcaError(f"já existe um arquivo em {caminho}")
        cofre = Vault.new(nome or caminho.stem)
        cabecalho = vault_file.save(caminho, cofre, credenciais, opcoes or SaveOptions())
        self._assumir(cofre, caminho, credenciais, cabecalho, somente_leitura=False)
        self._emitir(EVENTO_ABERTO)

    def open(self, caminho: Path, credenciais: Credentials,
             somente_leitura: bool = False, forcar_trava: bool = False) -> None:
        aberto = vault_file.load(caminho, credenciais)
        trava = None
        if not somente_leitura:
            trava = VaultLock(caminho)
            try:
                trava.acquire(forcar=forcar_trava)
            except ArcaError:
                trava = None
                raise
        self._assumir(aberto.vault, caminho, credenciais, aberto.header, somente_leitura)
        self._lock = trava
        self._emitir(EVENTO_ABERTO)

    def save(self, opcoes: SaveOptions | None = None) -> None:
        if self.state.read_only:
            raise ArcaError("cofre aberto somente para leitura")
        if self.state.path is None or self._credentials is None:
            raise VaultLockedError("nenhum cofre aberto para salvar")
        escolhas = opcoes or self._opcoes_atuais()
        self.state.header = vault_file.save(
            self.state.path, self.vault, self._credentials, escolhas
        )
        self.state.dirty = False
        self._emitir(EVENTO_SALVO)

    def save_as(self, caminho: Path, credenciais: Credentials | None = None,
                opcoes: SaveOptions | None = None) -> None:
        credenciais = credenciais or self._credentials
        if credenciais is None:
            raise VaultLockedError("nenhum cofre aberto")
        escolhas = opcoes or self._opcoes_atuais()
        cabecalho = vault_file.save(caminho, self.vault, credenciais, escolhas)
        if self._lock is not None:
            self._lock.release()
        self._credentials = credenciais
        self.state.path = caminho
        self.state.header = cabecalho
        self.state.read_only = False
        self.state.dirty = False
        self._lock = VaultLock(caminho)
        self._lock.acquire(forcar=True)
        self._emitir(EVENTO_SALVO)

    def change_credentials(self, novas: Credentials, opcoes: SaveOptions | None = None) -> None:
        if not self.is_open or self.state.path is None:
            raise VaultLockedError("nenhum cofre aberto")
        anteriores = self._credentials
        self._credentials = novas
        try:
            self.save(opcoes)
        except Exception:
            self._credentials = anteriores
            raise
        if anteriores is not None:
            anteriores.wipe()

    def close(self) -> None:
        """Tranca o cofre: descarta modelo, credenciais e trava de arquivo."""
        if self._lock is not None:
            self._lock.release()
            self._lock = None
        if self._credentials is not None:
            self._credentials.wipe()
            self._credentials = None
        self._vault = None
        self.state = SessionState()
        self._emitir(EVENTO_FECHADO)

    def _assumir(self, cofre: Vault, caminho: Path, credenciais: Credentials,
                 cabecalho: VaultHeader, somente_leitura: bool) -> None:
        if self.is_open:
            self.close()
        self._vault = cofre
        self._credentials = credenciais
        self.state = SessionState(
            path=caminho, header=cabecalho, read_only=somente_leitura, dirty=False
        )

    def _opcoes_atuais(self) -> SaveOptions:
        if self.state.header is None:
            return SaveOptions()
        return SaveOptions.from_header(self.state.header)

    # ------------------------------------------------------------------
    # Mutações
    # ------------------------------------------------------------------

    def mark_dirty(self) -> None:
        if not self.state.dirty:
            self.state.dirty = True
        self._emitir(EVENTO_MODIFICADO)

    def add_entry(self, grupo: Group, entrada: Entry) -> Entry:
        grupo.add_entry(entrada)
        self.mark_dirty()
        return entrada

    def update_entry(self, entrada: Entry, alteracoes: dict[str, Any]) -> None:
        """Aplica alterações campo a campo, guardando a versão anterior.

        Se nada mudou de fato, não empilha histórico nem suja o cofre: abrir e
        fechar a janela de edição sem mexer em nada não deve gerar uma versão.
        """
        if not self._alteracoes_efetivas(entrada, alteracoes):
            return
        entrada.push_history(self.vault.metadata.history_limit)
        for campo, valor in alteracoes.items():
            if campo == "password":
                entrada.password = ProtectedValue(valor)
            elif campo == "expires_at":
                entrada.times.expires_at = valor
            else:
                setattr(entrada, campo, valor)
        entrada.times.touch()
        self.mark_dirty()

    def delete_entry(self, entrada: Entry, permanente: bool = False) -> None:
        self.vault.delete_entry(entrada, permanente=permanente)
        self.mark_dirty()

    def add_group(self, pai: Group, grupo: Group) -> Group:
        pai.add_group(grupo)
        self.mark_dirty()
        return grupo

    def delete_group(self, grupo: Group, permanente: bool = False) -> None:
        self.vault.delete_group(grupo, permanente=permanente)
        self.mark_dirty()

    def move_entry(self, entrada: Entry, destino: Group) -> None:
        self.vault.move_entry(entrada, destino)
        self.mark_dirty()

    def move_group(self, grupo: Group, destino: Group) -> None:
        self.vault.move_group(grupo, destino)
        self.mark_dirty()

    def register_use(self, entrada: Entry) -> None:
        """Contabiliza uma cópia de senha, sem sujar o cofre por isso."""
        entrada.times.register_use()

    def empty_recycle_bin(self) -> int:
        removidos = self.vault.empty_recycle_bin()
        if removidos:
            self.mark_dirty()
        return removidos

    @staticmethod
    def _alteracoes_efetivas(entrada: Entry, alteracoes: dict[str, Any]) -> bool:
        for campo, novo in alteracoes.items():
            if campo == "password":
                if entrada.password.reveal() != novo:
                    return True
            elif campo == "expires_at":
                if entrada.times.expires_at != novo:
                    return True
            elif getattr(entrada, campo, None) != novo:
                return True
        return False
