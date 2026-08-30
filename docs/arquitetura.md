# Arquitetura

## Camadas

```
        ┌───────────────┐   ┌───────────────┐
        │  arca.gui     │   │  arca.cli     │      apresentação
        │  (PySide6)    │   │  (argparse)   │
        └───────┬───────┘   └───────┬───────┘
                └─────────┬─────────┘
                ┌─────────▼─────────┐
                │  arca.services    │              aplicação
                │  sessão, trava,   │
                │  importação/exp.  │
                └─────────┬─────────┘
                ┌─────────▼─────────┐
                │  arca.core        │              domínio
                │  modelo, cripto,  │
                │  formato, busca   │
                └───────────────────┘
```

A dependência aponta sempre para baixo. `core` não sabe que existe interface,
disco compartilhado ou sessão de usuário; `services` não sabe se quem chama é
uma janela ou um terminal.

O motivo prático é evitar a duplicação silenciosa de regra de negócio. Quando
histórico de versões, lixeira e marcação de "não salvo" vivem no serviço, a
CLI e a GUI não têm como divergir. A alternativa — cada interface manipulando
o modelo diretamente — funcionaria hoje e produziria comportamentos diferentes
na primeira mudança.

## `arca.core` — domínio

| Módulo               | Responsabilidade                                             |
|----------------------|--------------------------------------------------------------|
| `model.py`           | `Vault`, `Group`, `Entry`, `Times`, lixeira, histórico        |
| `secret.py`          | `SecretBytes`, `ProtectedValue` — contenção em memória        |
| `kdf.py`             | Argon2id, validação e calibração de parâmetros                |
| `keys.py`            | chave composta e derivação das chaves de trabalho             |
| `ciphers.py`         | AES-256-CBC e ChaCha20                                        |
| `hmacblock.py`       | fluxo de blocos autenticados                                  |
| `protectedstream.py` | keystream ChaCha20 dos campos protegidos                      |
| `header.py`          | cabeçalhos externo e interno (TLV)                            |
| `codec.py`           | modelo ⇄ payload JSON                                         |
| `vault_file.py`      | leitura e gravação do `.arca`                                 |
| `generator.py`       | senhas e frases-senha                                         |
| `strength.py`        | estimativa de entropia                                        |
| `search.py`          | linguagem de consulta                                         |
| `audit.py`           | relatório de saúde do cofre                                   |
| `wordlists.py`       | listas de palavras empacotadas                                |

`vault_file.py` é o único módulo que conhece o formato completo. Todo o resto
trabalha com objetos.

## `arca.services` — aplicação

- **`vault_service.py`** — a sessão. Mantém o cofre aberto, as credenciais (que
  a próxima gravação vai precisar, já que o sal muda a cada salvamento), o
  estado "não salvo" e a lista de observadores. Concentra as regras de mutação:
  `update_entry` empilha histórico apenas quando algo mudou de fato, `delete_*`
  decide entre lixeira e remoção definitiva, `close` descarta tudo de uma vez.
- **`filelock.py`** — trava consultiva por arquivo irmão, com detecção de
  travas órfãs de processos que já terminaram nesta máquina.
- **`porting.py`** — CSV de entrada e de saída, incluindo o reconhecimento de
  cabeçalhos de outros gerenciadores.

## `arca.cli` — terminal

Cada execução abre o cofre, faz uma coisa e sai; não há processo residente
guardando chave em memória. O preço é uma derivação Argon2id por comando; o
ganho é que fechar o terminal já tranca tudo.

O parser inteiro fica em `cli/main.py`, e não espalhado pelos módulos de
comando, porque a saída de `--help` é parte da documentação do programa: ler
`_construir_parser` de cima a baixo deve bastar para saber o que a ferramenta
faz.

## `arca.gui` — interface gráfica

```
app.py                 controlador: alterna entre destravado e trancado
├─ dialogs/            abertura, criação, entrada, gerador, auditoria…
├─ windows/            janela principal (três painéis)
├─ models/             QAbstractItemModel sobre o modelo de domínio
├─ widgets/            campo de senha, barra de força, painel de detalhes
├─ services/           área de transferência temporizada, vigia de inatividade
└─ settings.py         QSettings: recentes, geometria, preferências
```

Três decisões que valem registro:

**Os modelos Qt envolvem o domínio, não o copiam.** `GroupTreeModel` usa o
próprio objeto `Group` como ponteiro interno do índice. Isso só é seguro
porque a árvore inteira pertence ao `Vault` e vive exatamente enquanto o cofre
estiver aberto — ao trancar, modelo e janela são descartados juntos.

**O Argon2id sai da thread da interface.** Uma derivação leva centenas de
milissegundos; feita na thread da interface, congelaria a janela justamente no
momento em que o usuário mais espera retorno. Abertura e criação rodam em
`QThread`, com barra de progresso indeterminada.

**Trancar não encerra o programa.** O controlador desliga
`quitOnLastWindowClosed` e gerencia o encerramento explicitamente, para que a
janela principal possa fechar e dar lugar à tela de destravamento sem que o Qt
derrube o processo no meio do caminho.

## Fluxo de uma abertura

```
UnlockDialog
   └─ QThread ─ VaultService.open
                   ├─ vault_file.load
                   │     ├─ read_header            (TLV em claro)
                   │     ├─ verify_header_digest   (SHA-256)
                   │     ├─ derive                 (Argon2id)  ← o custo
                   │     ├─ verify_header_mac      (HMAC)
                   │     ├─ read_blocks            (HMAC por bloco)
                   │     ├─ decrypt
                   │     ├─ gzip.decompress
                   │     └─ codec.load_payload     (desmascara os campos)
                   └─ VaultLock.acquire
   └─ MainWindow(servico)
```

## Testes

| Arquivo             | Alvo                                                     |
|---------------------|----------------------------------------------------------|
| `test_crypto.py`    | cifras, KDF, derivação, blocos autenticados, keystream    |
| `test_vault_file.py`| ida e volta, credenciais, adulteração                    |
| `test_model.py`     | árvore, histórico, lixeira, serviço, trava de arquivo     |
| `test_tools.py`     | gerador, força, busca, auditoria                          |
| `test_cli.py`       | comandos de ponta a ponta, importação e exportação        |
| `test_gui.py`       | fumaça da interface, com a plataforma Qt "offscreen"      |

Os testes de interface constroem widgets e percorrem sinais de verdade, sem
desenhar nada na tela, de modo que a suíte roda em máquina sem sessão gráfica.
Toda a suíte usa os parâmetros mínimos de Argon2id: com os valores de produção,
o tempo seria gasto derivando chave, não testando.
