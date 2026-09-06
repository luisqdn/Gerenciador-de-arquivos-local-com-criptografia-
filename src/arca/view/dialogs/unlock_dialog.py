"""Tela de abertura: destravar um cofre existente ou criar um novo.

A derivação Argon2id leva centenas de milissegundos por construção. Rodá-la
na thread da interface congelaria a janela e passaria a impressão de travamento
justamente no momento em que o usuário mais precisa de retorno, então ela vai
para uma thread auxiliar e a janela mostra um indicador de progresso.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from arca import APP_NAME, VAULT_SUFFIX
from arca.controller.vault_controller import VaultController
from arca.model.armazenamento import Credenciais
from arca.model.erros import ErroArca

# Código de retorno próprio: o usuário pediu para criar um cofre em vez de abrir.
CODIGO_CRIAR = 2


class _Trabalhador(QObject):
    """Executa a abertura fora da thread da interface."""

    concluido = Signal(object)   # VaultController
    falhou = Signal(str)

    def __init__(self, caminho: Path, senha: str, somente_leitura: bool) -> None:
        super().__init__()
        self._caminho = caminho
        self._senha = senha
        self._somente_leitura = somente_leitura

    def executar(self) -> None:
        try:
            credenciais = Credenciais.a_partir_de(self._senha or None)
            servico = VaultController()
            servico.open(self._caminho, credenciais, somente_leitura=self._somente_leitura)
        except ErroArca as exc:
            self.falhou.emit(str(exc))
        except Exception as exc:  # falha inesperada: melhor mostrar que engolir
            self.falhou.emit(f"erro inesperado ao abrir o cofre: {exc}")
        else:
            self.concluido.emit(servico)


class UnlockDialog(QDialog):
    def __init__(self, parent: QWidget | None = None,
                 caminho_inicial: Path | None = None) -> None:
        super().__init__(parent)
        self._servico: VaultController | None = None
        self._thread: QThread | None = None
        self._trabalhador: _Trabalhador | None = None

        self.setWindowTitle(f"{APP_NAME} — abrir cofre")
        self.setMinimumWidth(480)

        self._cofre = QLineEdit(self)
        self._cofre.setPlaceholderText(f"caminho do arquivo *{VAULT_SUFFIX}")
        if caminho_inicial is not None:
            self._cofre.setText(str(caminho_inicial))

        procurar = QPushButton("Procurar…", self)
        procurar.setAutoDefault(False)
        procurar.clicked.connect(self._procurar_cofre)

        linha_cofre = QHBoxLayout()
        linha_cofre.addWidget(self._cofre, 1)
        linha_cofre.addWidget(procurar)

        self._senha = QLineEdit(self)
        self._senha.setEchoMode(QLineEdit.EchoMode.Password)
        self._senha.setPlaceholderText("senha mestra")
        self._senha.returnPressed.connect(self._destravar)

        self._somente_leitura = QCheckBox("Abrir somente para leitura", self)
        self._somente_leitura.setToolTip(
            "Impede gravações acidentais: o cofre abre, mas não pode ser salvo."
        )

        self._mensagem = QLabel(self)
        self._mensagem.setObjectName("rotuloErro")
        self._mensagem.setWordWrap(True)
        self._mensagem.setVisible(False)

        self._progresso = QProgressBar(self)
        self._progresso.setRange(0, 0)
        self._progresso.setTextVisible(False)
        self._progresso.setVisible(False)
        self._progresso.setFixedHeight(6)

        self._botoes = QDialogButtonBox(self)
        self._destravar_botao = self._botoes.addButton(
            "Destravar", QDialogButtonBox.ButtonRole.AcceptRole
        )
        criar = self._botoes.addButton("Criar cofre novo…",
                                       QDialogButtonBox.ButtonRole.ActionRole)
        criar.setAutoDefault(False)
        criar.clicked.connect(lambda: self.done(CODIGO_CRIAR))
        self._botoes.addButton("Cancelar", QDialogButtonBox.ButtonRole.RejectRole)
        self._botoes.accepted.connect(self._destravar)
        self._botoes.rejected.connect(self.reject)
        self._destravar_botao.setDefault(True)

        formulario = QFormLayout()
        formulario.addRow("Cofre", linha_cofre)
        formulario.addRow("Senha mestra", self._senha)
        formulario.addRow("", self._somente_leitura)

        leiaute = QVBoxLayout(self)
        leiaute.addLayout(formulario)
        leiaute.addWidget(self._mensagem)
        leiaute.addWidget(self._progresso)
        leiaute.addWidget(self._botoes)

        self._senha.setFocus()

    # ------------------------------------------------------------------

    def service(self) -> VaultController | None:
        return self._servico

    # ------------------------------------------------------------------

    def _procurar_cofre(self) -> None:
        caminho, _ = QFileDialog.getOpenFileName(
            self, "Abrir cofre", "",
            f"Cofres do {APP_NAME} (*{VAULT_SUFFIX});;Todos os arquivos (*)",
        )
        if caminho:
            self._cofre.setText(caminho)
            self._senha.setFocus()

    def _destravar(self) -> None:
        texto = self._cofre.text().strip()
        if not texto:
            self._erro("Escolha o arquivo do cofre.")
            return
        caminho = Path(texto)
        if not caminho.exists():
            self._erro(f"Arquivo não encontrado: {caminho}")
            return
        if not self._senha.text():
            self._erro("Informe a senha mestra.")
            return

        self._ocupado(True)
        trabalhador = _Trabalhador(
            caminho,
            self._senha.text(),
            self._somente_leitura.isChecked(),
        )
        thread = QThread(self)
        trabalhador.moveToThread(thread)
        thread.started.connect(trabalhador.executar)
        trabalhador.concluido.connect(self._ao_abrir)
        trabalhador.falhou.connect(self._ao_falhar)
        trabalhador.concluido.connect(thread.quit)
        trabalhador.falhou.connect(thread.quit)
        thread.finished.connect(trabalhador.deleteLater)
        # O trabalhador precisa de uma referencia do lado Python enquanto a
        # thread roda. Sem ela, ele e coletado assim que este metodo retorna --
        # as conexoes de sinal nao seguram o objeto -- e `started` nao encontra
        # mais o slot: a thread sobe, nada executa e a janela fica no indicador
        # de progresso para sempre.
        self._trabalhador = trabalhador
        self._thread = thread
        thread.start()

    def _ao_abrir(self, servico: VaultController) -> None:
        self._ocupado(False)
        self._servico = servico
        self.accept()

    def _ao_falhar(self, mensagem: str) -> None:
        self._ocupado(False)
        self._erro(mensagem)
        self._senha.selectAll()
        self._senha.setFocus()

    def _ocupado(self, ativo: bool) -> None:
        self._progresso.setVisible(ativo)
        self._destravar_botao.setEnabled(not ativo)
        self._senha.setEnabled(not ativo)
        self._cofre.setEnabled(not ativo)
        if ativo:
            self._mensagem.setVisible(False)
            self.setCursor(Qt.CursorShape.BusyCursor)
        else:
            self.unsetCursor()

    def _erro(self, mensagem: str) -> None:
        self._mensagem.setText(mensagem)
        self._mensagem.setVisible(True)

    def closeEvent(self, evento) -> None:  # noqa: N802 (API do Qt)
        if self._thread is not None and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(3000)
        super().closeEvent(evento)
