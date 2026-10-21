"""Aparência da interface."""

from __future__ import annotations

from importlib.resources import files

from PySide6.QtWidgets import QApplication

ARQUIVO_ESTILO = "tema.qss"


def aplicar_tema(app: QApplication) -> None:
    app.setStyle("Fusion")
    app.setStyleSheet(carregar_estilo())


def carregar_estilo() -> str:
    try:
        return files("arca.view").joinpath(ARQUIVO_ESTILO).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError):
        return ""
