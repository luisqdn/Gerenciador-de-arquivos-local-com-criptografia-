"""Aparência da interface.

O Arca não impõe um tema próprio: usa o estilo Fusion, que respeita a paleta
do sistema e se comporta igual em Windows, Linux e macOS, e aplica por cima
apenas os ajustes que a aplicação precisa -- rótulos discretos, texto de erro,
destaque do valor da senha. Assim o programa continua legível se o usuário
estiver em modo escuro, sem manter duas folhas de estilo em paralelo.
"""

from __future__ import annotations

from importlib.resources import files

from PySide6.QtWidgets import QApplication

ARQUIVO_ESTILO = "tema.qss"


def aplicar_tema(app: QApplication) -> None:
    app.setStyle("Fusion")
    app.setStyleSheet(carregar_estilo())


def carregar_estilo() -> str:
    try:
        return files("arca.gui.resources").joinpath(ARQUIVO_ESTILO).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError):
        return ""
