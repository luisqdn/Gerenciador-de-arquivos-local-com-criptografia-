"""Ponto de entrada da interface gráfica.

O controlador alterna entre dois estados: cofre trancado, com a tela de
destravamento em primeiro plano, e cofre aberto, com a janela principal. A
transição acontece nos dois sentidos -- trancar não encerra o programa, e o
usuário pode destravar outro cofre sem reiniciar.

`setQuitOnLastWindowClosed(False)` é necessário justamente por causa disso:
sem ele, o Qt encerraria o processo no instante em que a janela principal
fechasse para dar lugar à tela de destravamento.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PySide6.QtCore import QObject
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from arca import APP_NAME, APP_VERSION
from arca.core.errors import ArcaError
from arca.gui.dialogs.new_vault_dialog import NewVaultDialog
from arca.gui.dialogs.unlock_dialog import CODIGO_CRIAR, UnlockDialog
from arca.gui.settings import SettingsStore
from arca.gui.theme import aplicar_tema
from arca.gui.windows.main_window import MainWindow
from arca.services.vault_service import VaultService


class ArcaController(QObject):
    def __init__(self, app: QApplication, caminho_inicial: Path | None = None) -> None:
        super().__init__()
        self._app = app
        self._settings = SettingsStore()
        self._janela: MainWindow | None = None
        self._caminho_inicial = caminho_inicial

    def start(self) -> bool:
        """Abre a primeira sessão. Devolve False se o usuário desistir."""
        return self._abrir_sessao()

    def _abrir_sessao(self) -> bool:
        while True:
            dialogo = UnlockDialog(self._settings, caminho_inicial=self._caminho_inicial)
            self._caminho_inicial = None
            resultado = dialogo.exec()

            if resultado == QDialog.DialogCode.Accepted:
                servico = dialogo.service()
                if servico is not None:
                    self._mostrar_janela(servico)
                    return True
            elif resultado == CODIGO_CRIAR:
                criador = NewVaultDialog(self._settings)
                if criador.exec() == QDialog.DialogCode.Accepted:
                    servico = criador.service()
                    if servico is not None:
                        self._mostrar_janela(servico)
                        return True
                continue
            else:
                return False

    def _mostrar_janela(self, servico: VaultService) -> None:
        janela = MainWindow(servico, self._settings)
        janela.travado.connect(self._ao_trancar)
        janela.encerrado.connect(self._ao_encerrar)
        janela.show()
        self._janela = janela

    def _ao_trancar(self) -> None:
        self._descartar_janela()
        if not self._abrir_sessao():
            self._app.quit()

    def _ao_encerrar(self) -> None:
        self._descartar_janela()
        self._app.quit()

    def _descartar_janela(self) -> None:
        if self._janela is not None:
            self._janela.deleteLater()
            self._janela = None


def main(argv: list[str] | None = None) -> int:
    args = _analisar(argv if argv is not None else sys.argv[1:])

    QGuiApplication.setApplicationName(APP_NAME)
    QGuiApplication.setApplicationVersion(APP_VERSION)
    QGuiApplication.setOrganizationName(APP_NAME)

    app = QApplication(sys.argv[:1])
    app.setQuitOnLastWindowClosed(False)
    aplicar_tema(app)

    controlador = ArcaController(app, Path(args.cofre) if args.cofre else None)
    try:
        if not controlador.start():
            return 0
    except ArcaError as exc:
        QMessageBox.critical(None, APP_NAME, str(exc))
        return 1
    return app.exec()


def _analisar(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="arca-gui",
        description=f"{APP_NAME} - interface gráfica do gerenciador de senhas.",
    )
    parser.add_argument("cofre", nargs="?", help="cofre a abrir ao iniciar")
    parser.add_argument("--versao", action="version", version=f"{APP_NAME} {APP_VERSION}")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
