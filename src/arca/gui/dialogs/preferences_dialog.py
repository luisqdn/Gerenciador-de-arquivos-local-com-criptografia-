"""Preferências da aplicação."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from arca.gui.settings import Preferences


class PreferencesDialog(QDialog):
    def __init__(self, prefs: Preferences, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Preferências")
        self.setMinimumWidth(460)

        self._autolock = QSpinBox(self)
        self._autolock.setRange(0, 3600)
        self._autolock.setSingleStep(30)
        self._autolock.setValue(prefs.autolock_seconds)
        self._autolock.setSuffix(" s")
        self._autolock.setSpecialValueText("desligado")

        self._minimizar = QCheckBox("Minimizar a janela ao trancar", self)
        self._minimizar.setChecked(prefs.minimize_on_lock)

        self._clipboard = QSpinBox(self)
        self._clipboard.setRange(0, 300)
        self._clipboard.setSingleStep(5)
        self._clipboard.setValue(prefs.clipboard_seconds)
        self._clipboard.setSuffix(" s")
        self._clipboard.setSpecialValueText("nunca limpar")

        self._coluna_senha = QCheckBox("Mostrar a coluna de senhas na lista", self)
        self._coluna_senha.setChecked(prefs.show_password_column)

        self._confirmar = QCheckBox("Pedir confirmação ao remover entradas", self)
        self._confirmar.setChecked(prefs.confirm_on_delete)

        self._backup = QCheckBox("Manter cópia .bak do estado anterior a cada gravação", self)
        self._backup.setChecked(prefs.backup_on_save)

        self._salvar_ao_sair = QCheckBox("Salvar automaticamente ao fechar", self)
        self._salvar_ao_sair.setChecked(prefs.save_on_close)

        seguranca = QGroupBox("Segurança", self)
        formulario = QFormLayout(seguranca)
        formulario.addRow("Trancar após inatividade de", self._autolock)
        formulario.addRow("", self._minimizar)
        formulario.addRow("Limpar a área de transferência após", self._clipboard)
        formulario.addRow("", self._confirmar)

        arquivo = QGroupBox("Arquivo", self)
        outro = QFormLayout(arquivo)
        outro.addRow("", self._backup)
        outro.addRow("", self._salvar_ao_sair)

        aparencia = QGroupBox("Lista de entradas", self)
        visual = QFormLayout(aparencia)
        visual.addRow("", self._coluna_senha)

        nota = QLabel(
            "A contagem de inatividade observa o teclado e o mouse dentro do Arca. "
            "Trabalhar em outro programa também conta como inatividade, e o cofre "
            "será trancado.",
            self,
        )
        nota.setWordWrap(True)
        nota.setObjectName("rotuloDiscreto")

        botoes = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            parent=self,
        )
        botoes.accepted.connect(self.accept)
        botoes.rejected.connect(self.reject)

        leiaute = QVBoxLayout(self)
        leiaute.addWidget(seguranca)
        leiaute.addWidget(arquivo)
        leiaute.addWidget(aparencia)
        leiaute.addWidget(nota)
        leiaute.addWidget(botoes)

    def preferences(self) -> Preferences:
        return Preferences(
            autolock_seconds=self._autolock.value(),
            clipboard_seconds=self._clipboard.value(),
            minimize_on_lock=self._minimizar.isChecked(),
            show_password_column=self._coluna_senha.isChecked(),
            confirm_on_delete=self._confirmar.isChecked(),
            backup_on_save=self._backup.isChecked(),
            save_on_close=self._salvar_ao_sair.isChecked(),
        )
