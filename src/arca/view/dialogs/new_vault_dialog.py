"""Criação de um cofre novo."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from arca import APP_NAME, VAULT_SUFFIX
from arca.controller.vault_controller import VaultController
from arca.crypto.forca import Nivel, avaliar
from arca.model.armazenamento import Credenciais, OpcoesDeGravacao
from arca.model.erros import ErroArca
from arca.view.dialogs.generator_dialog import pedir_senha_gerada
from arca.view.widgets.password_edit import PasswordEdit

BITS_RECOMENDADOS = 60


class _Criador(QObject):
    concluido = Signal(object)
    falhou = Signal(str)

    def __init__(self, caminho: Path, nome: str, credenciais: Credenciais,
                 opcoes: OpcoesDeGravacao) -> None:
        super().__init__()
        self._caminho = caminho
        self._nome = nome
        self._credenciais = credenciais
        self._opcoes = opcoes

    def executar(self) -> None:
        try:
            servico = VaultController()
            servico.create(self._caminho, self._credenciais, self._opcoes, self._nome)
        except ErroArca as exc:
            self.falhou.emit(str(exc))
        except Exception as exc:
            self.falhou.emit(f"erro inesperado ao criar o cofre: {exc}")
        else:
            self.concluido.emit(servico)


class NewVaultDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._servico: VaultController | None = None
        self._thread: QThread | None = None
        self._criador: _Criador | None = None

        self.setWindowTitle(f"{APP_NAME} — novo cofre")
        self.setMinimumWidth(540)

        self._arquivo = QLineEdit(self)
        self._arquivo.setPlaceholderText(f"caminho do arquivo {VAULT_SUFFIX}")
        escolher = QPushButton("Escolher…", self)
        escolher.setAutoDefault(False)
        escolher.clicked.connect(self._escolher_destino)
        linha_arquivo = QHBoxLayout()
        linha_arquivo.addWidget(self._arquivo, 1)
        linha_arquivo.addWidget(escolher)

        self._nome = QLineEdit(self)
        self._nome.setPlaceholderText("Cofre pessoal")

        self._senha = PasswordEdit(self, com_copia=False)
        self._senha.set_placeholder("senha mestra")
        self._senha.changed.connect(self._revalidar)
        self._senha.generate_requested.connect(self._gerar_senha_mestra)

        self._repetir = QLineEdit(self)
        self._repetir.setEchoMode(QLineEdit.EchoMode.Password)
        self._repetir.setPlaceholderText("repita a senha mestra")
        self._repetir.textChanged.connect(self._revalidar)

        self._aviso = QLabel(self)
        self._aviso.setObjectName("rotuloErro")
        self._aviso.setWordWrap(True)

        self._progresso = QProgressBar(self)
        self._progresso.setRange(0, 0)
        self._progresso.setTextVisible(False)
        self._progresso.setFixedHeight(6)
        self._progresso.setVisible(False)

        self._botoes = QDialogButtonBox(self)
        self._criar = self._botoes.addButton("Criar cofre", QDialogButtonBox.ButtonRole.AcceptRole)
        self._botoes.addButton("Cancelar", QDialogButtonBox.ButtonRole.RejectRole)
        self._botoes.accepted.connect(self._criar_cofre)
        self._botoes.rejected.connect(self.reject)

        formulario = QFormLayout()
        formulario.addRow("Arquivo", linha_arquivo)
        formulario.addRow("Nome", self._nome)
        formulario.addRow("Senha mestra", self._senha)
        formulario.addRow("Confirmação", self._repetir)

        leiaute = QVBoxLayout(self)
        leiaute.addLayout(formulario)
        leiaute.addWidget(self._aviso)
        leiaute.addWidget(self._progresso)
        leiaute.addWidget(self._botoes)

        self._revalidar()

    def service(self) -> VaultController | None:
        return self._servico

    def _gerar_senha_mestra(self) -> None:
        gerada = pedir_senha_gerada(self, frase=True)
        if not gerada:
            return
        self._senha.set_text(gerada)
        self._repetir.setText(gerada)
        self._senha.reveal(True)
        self._revalidar()

    def _escolher_destino(self) -> None:
        caminho, _ = QFileDialog.getSaveFileName(
            self, "Criar cofre", "",
            f"Cofres do {APP_NAME} (*{VAULT_SUFFIX});;Todos os arquivos (*)",
        )
        if not caminho:
            return
        if not caminho.endswith(VAULT_SUFFIX):
            caminho += VAULT_SUFFIX
        self._arquivo.setText(caminho)
        if not self._nome.text():
            self._nome.setText(Path(caminho).stem)
        self._revalidar()

    def _revalidar(self) -> None:
        senha = self._senha.text()
        problemas = []
        if not self._arquivo.text().strip():
            problemas.append("escolha onde salvar o cofre")
        if not senha:
            problemas.append("defina uma senha mestra")
        if senha and senha != self._repetir.text():
            problemas.append("a confirmação não confere")
        self._aviso.setText("; ".join(problemas).capitalize())
        self._criar.setEnabled(not problemas)

    def _criar_cofre(self) -> None:
        destino = Path(self._arquivo.text().strip())
        if destino.exists():
            QMessageBox.warning(self, "Arquivo existente",
                                f"Já existe um arquivo em {destino}.")
            return

        senha = self._senha.text()
        if senha:
            avaliacao = avaliar(senha)
            if avaliacao.nivel <= Nivel.FRACA:
                resposta = QMessageBox.question(
                    self, "Senha fraca",
                    f"Esta senha foi classificada como {avaliacao.nivel.rotulo} "
                    f"({avaliacao.bits:.0f} bits).\n\n"
                    "Ela protege todas as outras senhas do cofre. Usar mesmo assim?",
                )
                if resposta != QMessageBox.StandardButton.Yes:
                    return

        opcoes = OpcoesDeGravacao()
        credenciais = Credenciais.a_partir_de(senha or None)

        self._ocupado(True)
        criador = _Criador(destino, self._nome.text().strip() or destino.stem,
                           credenciais, opcoes)
        thread = QThread(self)
        criador.moveToThread(thread)
        thread.started.connect(criador.executar)
        criador.concluido.connect(self._ao_criar)
        criador.falhou.connect(self._ao_falhar)
        criador.concluido.connect(thread.quit)
        criador.falhou.connect(thread.quit)
        thread.finished.connect(criador.deleteLater)
        self._criador = criador
        self._thread = thread
        thread.start()

    def _ao_criar(self, servico: VaultController) -> None:
        self._ocupado(False)
        self._servico = servico
        self.accept()

    def _ao_falhar(self, mensagem: str) -> None:
        self._ocupado(False)
        QMessageBox.critical(self, "Não foi possível criar o cofre", mensagem)

    def _ocupado(self, ativo: bool) -> None:
        self._progresso.setVisible(ativo)
        self._criar.setEnabled(not ativo)

    def closeEvent(self, evento) -> None:  # noqa: N802 (API do Qt)
        if self._thread is not None and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(3000)
        super().closeEvent(evento)
