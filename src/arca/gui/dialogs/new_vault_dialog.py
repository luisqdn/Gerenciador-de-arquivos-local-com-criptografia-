"""Criação de um cofre novo."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from arca import APP_NAME, VAULT_SUFFIX
from arca.core.ciphers import CipherId
from arca.core.errors import ArcaError
from arca.core.kdf import KdfParameters, calibrate
from arca.core.strength import Level, evaluate
from arca.core.vault_file import Credentials, SaveOptions
from arca.gui.settings import SettingsStore
from arca.gui.widgets.password_edit import PasswordEdit
from arca.services.vault_service import VaultService

BITS_RECOMENDADOS = 60


class _Criador(QObject):
    concluido = Signal(object)
    falhou = Signal(str)

    def __init__(self, caminho: Path, nome: str, credenciais: Credentials,
                 opcoes: SaveOptions) -> None:
        super().__init__()
        self._caminho = caminho
        self._nome = nome
        self._credenciais = credenciais
        self._opcoes = opcoes

    def executar(self) -> None:
        try:
            servico = VaultService()
            servico.create(self._caminho, self._credenciais, self._opcoes, self._nome)
        except ArcaError as exc:
            self.falhou.emit(str(exc))
        except Exception as exc:
            self.falhou.emit(f"erro inesperado ao criar o cofre: {exc}")
        else:
            self.concluido.emit(servico)


class NewVaultDialog(QDialog):
    def __init__(self, settings: SettingsStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._settings = settings
        self._servico: VaultService | None = None
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

        self._repetir = QLineEdit(self)
        self._repetir.setEchoMode(QLineEdit.EchoMode.Password)
        self._repetir.setPlaceholderText("repita a senha mestra")
        self._repetir.textChanged.connect(self._revalidar)

        self._cifra = QComboBox(self)
        self._cifra.addItem(CipherId.AES256_CBC.rotulo, CipherId.AES256_CBC)
        self._cifra.addItem(CipherId.CHACHA20.rotulo, CipherId.CHACHA20)

        self._memoria = QSpinBox(self)
        self._memoria.setRange(8, 1024)
        self._memoria.setValue(64)
        self._memoria.setSuffix(" MiB")
        self._iteracoes = QSpinBox(self)
        self._iteracoes.setRange(1, 64)
        self._iteracoes.setValue(4)
        self._threads = QSpinBox(self)
        self._threads.setRange(1, 16)
        self._threads.setValue(4)

        calibrar = QPushButton("Calibrar nesta máquina", self)
        calibrar.setAutoDefault(False)
        calibrar.setToolTip("Ajusta as iterações para uma derivação de cerca de 0,6 s.")
        calibrar.clicked.connect(self._calibrar)

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

        avancado = QGroupBox("Parâmetros criptográficos", self)
        avancado.setCheckable(True)
        avancado.setChecked(False)
        interno = QFormLayout(avancado)
        interno.addRow("Cifra", self._cifra)
        interno.addRow("Memória do Argon2id", self._memoria)
        interno.addRow("Iterações", self._iteracoes)
        interno.addRow("Threads", self._threads)
        interno.addRow("", calibrar)

        leiaute = QVBoxLayout(self)
        leiaute.addLayout(formulario)
        leiaute.addWidget(avancado)
        leiaute.addWidget(self._aviso)
        leiaute.addWidget(self._progresso)
        leiaute.addWidget(self._botoes)

        self._revalidar()

    # ------------------------------------------------------------------

    def service(self) -> VaultService | None:
        return self._servico

    # ------------------------------------------------------------------

    def _escolher_destino(self) -> None:
        caminho, _ = QFileDialog.getSaveFileName(
            self, "Criar cofre", self._settings.last_directory(),
            f"Cofres do {APP_NAME} (*{VAULT_SUFFIX})",
        )
        if not caminho:
            return
        if not caminho.endswith(VAULT_SUFFIX):
            caminho += VAULT_SUFFIX
        self._arquivo.setText(caminho)
        if not self._nome.text():
            self._nome.setText(Path(caminho).stem)
        self._revalidar()

    def _calibrar(self) -> None:
        self.setEnabled(False)
        try:
            parametros = calibrate(0.6, memory_kib=self._memoria.value() * 1024,
                                   parallelism=self._threads.value())
        finally:
            self.setEnabled(True)
        self._iteracoes.setValue(parametros.iterations)
        QMessageBox.information(
            self, "Calibração concluída",
            f"{parametros.describe()}\n\n"
            "Estes parâmetros ficam gravados no cabeçalho do cofre e podem ser "
            "alterados depois, ao trocar a senha mestra.",
        )

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
            avaliacao = evaluate(senha)
            if avaliacao.level <= Level.FRACA:
                resposta = QMessageBox.question(
                    self, "Senha fraca",
                    f"Esta senha foi classificada como {avaliacao.level.rotulo} "
                    f"({avaliacao.bits:.0f} bits).\n\n"
                    "Ela protege todas as outras senhas do cofre. Usar mesmo assim?",
                )
                if resposta != QMessageBox.StandardButton.Yes:
                    return

        opcoes = SaveOptions(
            cipher=self._cifra.currentData(),
            kdf=KdfParameters(
                memory_kib=self._memoria.value() * 1024,
                iterations=self._iteracoes.value(),
                parallelism=self._threads.value(),
            ),
        )
        credenciais = Credentials.from_inputs(senha or None)

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
        # Mesma armadilha do UnlockDialog: sem uma referencia do lado Python o
        # criador e coletado ao fim deste metodo e `started` nao acha o slot.
        self._criador = criador
        self._thread = thread
        thread.start()

    def _ao_criar(self, servico: VaultService) -> None:
        self._ocupado(False)
        self._servico = servico
        if servico.path is not None:
            self._settings.push_recent(servico.path)
            self._settings.set_last_directory(servico.path.parent)
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
