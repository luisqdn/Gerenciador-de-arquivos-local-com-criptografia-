"""Troca da senha mestra de um cofre aberto."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from arca.core.kdf import KdfParameters, calibrate
from arca.core.strength import Level, evaluate
from arca.core.vault_file import Credentials
from arca.gui.widgets.password_edit import PasswordEdit


class MasterKeyDialog(QDialog):
    """Coleta os novos fatores. A regravação fica a cargo do VaultService."""

    def __init__(self, kdf_atual: KdfParameters, caminho_cofre: Path,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._caminho = caminho_cofre
        self.setWindowTitle("Alterar senha mestra")
        self.setMinimumWidth(520)

        self._senha = PasswordEdit(self, com_copia=False)
        self._senha.set_placeholder("nova senha mestra")
        self._senha.changed.connect(self._revalidar)

        self._repetir = QLineEdit(self)
        self._repetir.setEchoMode(QLineEdit.EchoMode.Password)
        self._repetir.setPlaceholderText("repita a nova senha")
        self._repetir.textChanged.connect(self._revalidar)

        self._memoria = QSpinBox(self)
        self._memoria.setRange(8, 1024)
        self._memoria.setValue(kdf_atual.memory_kib // 1024)
        self._memoria.setSuffix(" MiB")
        self._iteracoes = QSpinBox(self)
        self._iteracoes.setRange(1, 64)
        self._iteracoes.setValue(kdf_atual.iterations)
        self._threads = QSpinBox(self)
        self._threads.setRange(1, 16)
        self._threads.setValue(kdf_atual.parallelism)

        calibrar = QPushButton("Recalibrar", self)
        calibrar.setAutoDefault(False)
        calibrar.clicked.connect(self._calibrar)

        self._aviso = QLabel(self)
        self._aviso.setObjectName("rotuloErro")
        self._aviso.setWordWrap(True)

        explicacao = QLabel(
            "O cofre será regravado do zero, com sal e IV novos. O arquivo antigo "
            "fica preservado na cópia .bak até a próxima gravação.",
            self,
        )
        explicacao.setWordWrap(True)
        explicacao.setObjectName("rotuloDiscreto")

        self._botoes = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            parent=self,
        )
        self._botoes.button(QDialogButtonBox.StandardButton.Ok).setText("Alterar")
        self._botoes.accepted.connect(self._confirmar)
        self._botoes.rejected.connect(self.reject)

        formulario = QFormLayout()
        formulario.addRow("Nova senha", self._senha)
        formulario.addRow("Confirmação", self._repetir)
        formulario.addRow("Memória do Argon2id", self._memoria)
        formulario.addRow("Iterações", self._iteracoes)
        formulario.addRow("Threads", self._threads)
        formulario.addRow("", calibrar)

        leiaute = QVBoxLayout(self)
        leiaute.addLayout(formulario)
        leiaute.addWidget(explicacao)
        leiaute.addWidget(self._aviso)
        leiaute.addWidget(self._botoes)
        self._revalidar()

    # ------------------------------------------------------------------

    def credentials(self) -> Credentials:
        return Credentials.from_inputs(self._senha.text() or None)

    def kdf(self) -> KdfParameters:
        return KdfParameters(
            memory_kib=self._memoria.value() * 1024,
            iterations=self._iteracoes.value(),
            parallelism=self._threads.value(),
        )

    # ------------------------------------------------------------------

    def _calibrar(self) -> None:
        self.setEnabled(False)
        try:
            parametros = calibrate(0.6, memory_kib=self._memoria.value() * 1024,
                                   parallelism=self._threads.value())
        finally:
            self.setEnabled(True)
        self._iteracoes.setValue(parametros.iterations)

    def _revalidar(self) -> None:
        problemas = []
        senha = self._senha.text()
        if not senha:
            problemas.append("defina a nova senha mestra")
        if senha and senha != self._repetir.text():
            problemas.append("a confirmação não confere")
        self._aviso.setText("; ".join(problemas).capitalize())
        self._botoes.button(QDialogButtonBox.StandardButton.Ok).setEnabled(not problemas)

    def _confirmar(self) -> None:
        senha = self._senha.text()
        if senha:
            avaliacao = evaluate(senha)
            if avaliacao.level <= Level.FRACA:
                resposta = QMessageBox.question(
                    self, "Senha fraca",
                    f"A nova senha foi classificada como {avaliacao.level.rotulo} "
                    f"({avaliacao.bits:.0f} bits). Continuar?",
                )
                if resposta != QMessageBox.StandardButton.Yes:
                    return
        self.accept()
