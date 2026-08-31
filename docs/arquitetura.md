# Arquitetura

## As quatro camadas

```
                ┌───────────────────┐
                │  arca.view        │   apresentação
                │  (PySide6)        │   janela, diálogos, widgets
                └─────────┬─────────┘
                          │
                ┌─────────▼─────────┐
                │  arca.controller  │   orquestração
                │  sessão do cofre  │   e ciclo da aplicação
                └─────────┬─────────┘
                          │
                ┌─────────▼─────────┐
                │  arca.model       │   dados
                │  cofre, arquivo,  │
                │  busca            │
                └─────────┬─────────┘
                          │
                ┌─────────▼─────────┐
                │  arca.crypto      │   segurança
                │  KDF, cifras,     │
                │  HMAC, gerador    │
                └───────────────────┘
```

A dependência aponta sempre para baixo. `crypto` e `model` não sabem que
existe interface; `controller` não sabe qual widget o chamou.

O padrão é o MVC clássico, com uma diferença deliberada: a criptografia não
fica escondida dentro do Model. Ela é o assunto do trabalho, e uma camada
própria deixa isso visível na própria árvore de diretórios.

O motivo prático da separação é evitar a duplicação silenciosa de regra de
negócio. Quando "o que acontece ao trancar" e "quando o cofre está sujo" vivem
no Controller, nenhum diálogo pode divergir. A alternativa — cada janela
manipulando o modelo diretamente — funcionaria hoje e produziria
comportamentos diferentes na primeira mudança.

## `arca.model` — os dados

| Módulo       | Responsabilidade                                        |
|--------------|---------------------------------------------------------|
| `vault.py`   | `Vault`, `Group`, `Entry`, `Times`, lixeira             |
| `codec.py`   | modelo ⇄ payload JSON                                   |
| `header.py`  | cabeçalhos externo e interno (TLV)                      |
| `storage.py` | leitura e gravação do `.arca`                           |
| `search.py`  | linguagem de consulta                                   |
| `errors.py`  | hierarquia de exceções                                  |

`storage.py` é o único módulo que conhece o formato completo do arquivo. Todo
o resto trabalha com objetos.

## `arca.crypto` — a segurança

| Módulo         | Responsabilidade                                       |
|----------------|--------------------------------------------------------|
| `kdf.py`       | Argon2id, chave composta e derivação das chaves        |
| `ciphers.py`   | AES-256-CBC e ChaCha20                                 |
| `mac.py`       | fluxo de blocos autenticados                           |
| `stream.py`    | keystream ChaCha20 que mascara as senhas no payload    |
| `secret.py`    | `SecretBytes`, `ProtectedValue` — contenção em memória |
| `generator.py` | senhas e frases-senha                                  |
| `strength.py`  | estimativa de entropia                                 |
| `wordlists.py` | listas de palavras empacotadas                         |

A cadeia de chaves está documentada no topo de `kdf.py`: senha mestra →
chave composta (SHA-256) → chave transformada (Argon2id) → chave de cifragem
e semente de HMAC (SHA-512 com bytes de domínio distintos).

## `arca.controller` — a orquestração

- **`vault_controller.py`** — a sessão. Mantém o cofre aberto, as credenciais
  (que a próxima gravação vai precisar, já que o sal muda a cada salvamento),
  o estado "não salvo" e a lista de observadores. Concentra as regras de
  mutação: `update_entry` só suja o cofre quando algo mudou de fato,
  `delete_*` decide entre lixeira e remoção definitiva, `close` descarta tudo
  de uma vez.
- **`app_controller.py`** — o ciclo da aplicação. Alterna entre cofre
  trancado, com a tela de destravamento, e cofre aberto, com a janela
  principal.

## `arca.view` — a apresentação

```
main_window.py         janela de três painéis
adapters.py            GroupTreeModel e EntryTableModel sobre o domínio
clipboard.py           área de transferência temporizada
theme.py + tema.qss    estilo Fusion com ajustes pontuais
dialogs/               abertura, criação, entrada, gerador, senha mestra
widgets/               campo de senha, barra de força, painel de detalhes
```

Três decisões que valem registro:

**Os adaptadores Qt envolvem o domínio, não o copiam.** `GroupTreeModel` usa
o próprio objeto `Group` como ponteiro interno do índice. Isso só é seguro
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
UnlockDialog                                              (view)
   └─ QThread ─ VaultController.open                      (controller)
                   └─ model.storage.load                  (model)
                         ├─ read_header                   (TLV em claro)
                         ├─ verify_header_digest          (SHA-256)
                         ├─ kdf.derive                    (Argon2id)  ← o custo
                         ├─ verify_header_mac             (HMAC)
                         ├─ mac.read_blocks               (HMAC por bloco)
                         ├─ ciphers.decrypt
                         ├─ gzip.decompress
                         └─ codec.load_payload            (desmascara as senhas)
   └─ MainWindow(controlador)                             (view)
```

Vale reparar em quantas camadas a chamada atravessa e em qual direção: a View
pede, o Controller coordena, o Model lê o arquivo e delega a parte
criptográfica. Nenhuma seta aponta para cima.

## Testes

| Arquivo           | Alvo                                                     |
|-------------------|----------------------------------------------------------|
| `test_crypto.py`  | cifras, KDF, blocos, keystream, segredos, gerador, força  |
| `test_model.py`   | árvore, lixeira, busca, sessão do controlador             |
| `test_storage.py` | ida e volta, credenciais, adulteração                     |
| `test_view.py`    | fumaça da interface, com a plataforma Qt "offscreen"      |

Um arquivo por camada. Os testes de interface constroem widgets e percorrem
sinais de verdade, sem desenhar nada na tela, de modo que a suíte roda em
máquina sem sessão gráfica. Toda a suíte usa os parâmetros mínimos de
Argon2id: com os valores de produção, o tempo seria gasto derivando chave, não
testando.
