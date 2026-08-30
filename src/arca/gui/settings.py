"""Preferências da interface gráfica.

Guardadas via QSettings, que resolve sozinho onde escrever em cada sistema
(registro no Windows, plist no macOS, arquivo INI no Linux). Nada sensível
passa por aqui: apenas caminhos de cofres recentes, geometria de janela e
tempos de expiração. Senhas, chaves e conteúdo do cofre nunca saem do .arca.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QSettings

from arca import APP_NAME

ORGANIZACAO = "Arca"
MAXIMO_RECENTES = 8


@dataclass(slots=True)
class Preferences:
    autolock_seconds: int = 300
    clipboard_seconds: int = 20
    minimize_on_lock: bool = True
    show_password_column: bool = False
    confirm_on_delete: bool = True
    backup_on_save: bool = True
    save_on_close: bool = True


class SettingsStore:
    def __init__(self) -> None:
        self._qs = QSettings(ORGANIZACAO, APP_NAME)

    # ------------------------------------------------------------------
    # Preferências
    # ------------------------------------------------------------------

    def load(self) -> Preferences:
        padrao = Preferences()
        return Preferences(
            autolock_seconds=self._inteiro("autolock/segundos", padrao.autolock_seconds),
            clipboard_seconds=self._inteiro("clipboard/segundos", padrao.clipboard_seconds),
            minimize_on_lock=self._booleano("autolock/minimizar", padrao.minimize_on_lock),
            show_password_column=self._booleano("lista/coluna_senha",
                                                padrao.show_password_column),
            confirm_on_delete=self._booleano("geral/confirmar_exclusao",
                                             padrao.confirm_on_delete),
            backup_on_save=self._booleano("geral/backup", padrao.backup_on_save),
            save_on_close=self._booleano("geral/salvar_ao_sair", padrao.save_on_close),
        )

    def store(self, prefs: Preferences) -> None:
        self._qs.setValue("autolock/segundos", prefs.autolock_seconds)
        self._qs.setValue("clipboard/segundos", prefs.clipboard_seconds)
        self._qs.setValue("autolock/minimizar", prefs.minimize_on_lock)
        self._qs.setValue("lista/coluna_senha", prefs.show_password_column)
        self._qs.setValue("geral/confirmar_exclusao", prefs.confirm_on_delete)
        self._qs.setValue("geral/backup", prefs.backup_on_save)
        self._qs.setValue("geral/salvar_ao_sair", prefs.save_on_close)
        self._qs.sync()

    # ------------------------------------------------------------------
    # Cofres recentes
    # ------------------------------------------------------------------

    def recent_vaults(self) -> list[Path]:
        bruto = self._qs.value("recentes/lista", [], type=list)
        caminhos = [Path(str(item)) for item in bruto]
        return [c for c in caminhos if c.exists()]

    def push_recent(self, caminho: Path) -> None:
        atuais = [str(c) for c in self.recent_vaults() if c != caminho]
        atuais.insert(0, str(caminho))
        self._qs.setValue("recentes/lista", atuais[:MAXIMO_RECENTES])
        self._qs.sync()

    def forget_recent(self, caminho: Path) -> None:
        atuais = [str(c) for c in self.recent_vaults() if c != caminho]
        self._qs.setValue("recentes/lista", atuais)
        self._qs.sync()

    def last_directory(self) -> str:
        return str(self._qs.value("recentes/diretorio", str(Path.home())))

    def set_last_directory(self, caminho: Path) -> None:
        self._qs.setValue("recentes/diretorio", str(caminho))

    # ------------------------------------------------------------------
    # Geometria
    # ------------------------------------------------------------------

    def save_geometry(self, chave: str, dados: bytes) -> None:
        self._qs.setValue(f"geometria/{chave}", dados)

    def load_geometry(self, chave: str) -> bytes | None:
        valor = self._qs.value(f"geometria/{chave}")
        return bytes(valor) if valor else None

    def _inteiro(self, chave: str, padrao: int) -> int:
        try:
            return int(self._qs.value(chave, padrao))
        except (TypeError, ValueError):
            return padrao

    def _booleano(self, chave: str, padrao: bool) -> bool:
        valor = self._qs.value(chave, padrao)
        if isinstance(valor, bool):
            return valor
        return str(valor).casefold() in {"true", "1", "sim"}
