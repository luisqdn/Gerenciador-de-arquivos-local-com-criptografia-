# Arca

Gerenciador de senhas local. O cofre é um único arquivo criptografado que fica
na sua máquina — não há sincronização, servidor, conta ou telemetria. O
programa nunca abre um socket.

O projeto foi escrito como trabalho de conclusão de curso, e por isso a
documentação explica não só o que o código faz, mas por que cada decisão foi
tomada. O formato de arquivo está especificado em
[docs/formato-do-arquivo.md](docs/formato-do-arquivo.md), a arquitetura em
[docs/arquitetura.md](docs/arquitetura.md), e os limites da proteção em
[docs/modelo-de-ameacas.md](docs/modelo-de-ameacas.md).

![Janela principal do Arca](docs/imagens/janela-principal.png)

## O que ele faz

- Cofre em arquivo único (`.arca`), cifrado com AES-256 ou ChaCha20 e
  autenticado por HMAC-SHA256 em blocos.
- Senha mestra derivada por Argon2id, com parâmetros calibráveis e gravados no
  próprio cofre.
- Organização em grupos aninhados, campos personalizados, etiquetas, datas de
  validade, histórico de versões por entrada e lixeira.
- Gerador de senhas e de frases-senha, com entropia calculada por construção.
- Estimador de força que reconhece palavras de dicionário, sequências,
  repetições e senhas de vazamentos conhecidos.
- Auditoria offline do cofre: senhas repetidas, fracas, vencidas ou antigas.
- Busca com filtros (`usuario:ana url:gov.br`), que nunca pesquisa dentro de
  senhas.
- Bloqueio automático por inatividade e limpeza temporizada da área de
  transferência.
- Importação e exportação em CSV, inclusive de cabeçalhos de outros
  gerenciadores.
- Interface gráfica e linha de comando sobre o mesmo núcleo.

## Instalação

Requer Python 3.11 ou superior.

```bash
git clone <repositório> arca
cd arca

python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux e macOS
source .venv/bin/activate

pip install -e ".[gui]"
```

Sem `[gui]`, apenas a linha de comando é instalada — útil em servidores. Para
rodar os testes, use `pip install -e ".[gui,dev]"`.

## Uso — interface gráfica

```bash
arca-gui                    # abre a tela de destravamento
arca-gui pessoal.arca       # já aponta para um cofre
```

![Tela de destravamento](docs/imagens/tela-de-abertura.png)

Na primeira execução, use **Criar cofre novo…** na tela de abertura. O botão
**Calibrar nesta máquina**, na seção de parâmetros criptográficos, ajusta as
iterações do Argon2id para uma derivação de cerca de 0,6 segundo no seu
hardware — vale a pena usá-lo.

Atalhos: `Ctrl+C` copia a senha, `Ctrl+B` copia o usuário, `Ctrl+U` abre o
endereço, `Ctrl+N` cria entrada, `Ctrl+P` abre o gerador, `Ctrl+H` abre a
auditoria e `Ctrl+L` tranca o cofre.

## Uso — linha de comando

```bash
# criar um cofre, medindo o custo do Argon2id nesta máquina
arca novo pessoal.arca --calibrar

# adicionar uma entrada com senha gerada de 24 caracteres
arca add pessoal.arca --titulo "Banco" --usuario ana --grupo Bancos --gerar 24

# procurar
arca listar pessoal.arca --arvore
arca buscar pessoal.arca "usuario:ana url:gov.br"

# copiar a senha e limpar a área de transferência depois de 20 s
arca ver pessoal.arca banco --copiar

# verificar a saúde do cofre
arca auditar pessoal.arca

# gerar segredos sem abrir cofre nenhum
arca gerar -n 5 -t 24
arca gerar --frase --palavras 6
arca forca                       # lê a senha sem eco e avalia
```

`arca --help` lista todos os comandos; cada um aceita `--help` próprio.

Nenhum comando aceita a senha mestra como argumento visível na ajuda: a linha
de comando aparece na lista de processos e costuma ir parar no histórico do
shell. Quando a entrada padrão não é um terminal, a senha é lida de `stdin`,
o que permite scripts:

```bash
echo "$SENHA" | arca listar pessoal.arca
```

### Comandos

| Comando     | Para quê                                            |
|-------------|-----------------------------------------------------|
| `novo`      | cria um cofre                                       |
| `info`      | mostra os parâmetros criptográficos do arquivo      |
| `listar`    | lista entradas, em tabela ou em árvore              |
| `buscar`    | procura por texto ou filtros                        |
| `ver`       | exibe uma entrada, opcionalmente copiando a senha   |
| `add`       | cria uma entrada                                    |
| `editar`    | altera uma entrada, guardando a versão anterior     |
| `remover`   | manda para a lixeira                                |
| `grupo`     | cria ou remove grupos                               |
| `lixeira`   | lista ou esvazia                                    |
| `auditar`   | procura senhas fracas, repetidas ou vencidas        |
| `senha`     | troca a senha mestra                                |
| `exportar`  | grava tudo em CSV, sem proteção                     |
| `importar`  | traz entradas de um CSV                             |
| `gerar`     | gera senhas, frases-senha ou PINs                   |
| `forca`     | avalia a força de uma senha                         |
| `medir`     | mede o custo do Argon2id nesta máquina              |

## Segurança em resumo

| Componente                | Escolha                                          |
|---------------------------|--------------------------------------------------|
| Derivação de chave        | Argon2id (64 MiB, 4 iterações, 4 threads)        |
| Cifragem                  | AES-256-CBC ou ChaCha20                          |
| Autenticação              | HMAC-SHA256 por bloco, encrypt-then-MAC          |
| Campos sensíveis          | mascarados por keystream ChaCha20 no payload     |
| Aleatoriedade             | `secrets` e `os.urandom`, nunca `random`         |

Sal e IV são sorteados a cada gravação, o que troca a chave de cifragem a cada
salvamento. O cabeçalho, ainda que em texto claro, é autenticado: alterá-lo
para rebaixar o custo do Argon2id derruba a verificação.

**Não há recuperação.** Perder a senha mestra significa perder o conteúdo:
não há pergunta de segurança, e-mail de recuperação nem porta dos fundos. Faça
cópias de segurança do `.arca`.

## Desenvolvimento

```bash
pytest                      # suíte completa
pytest --cov=arca           # com cobertura
ruff check src tests        # análise estática
```

A suíte cobre a criptografia, o formato de arquivo, o modelo, a linha de
comando e a interface gráfica. Os testes de interface rodam com a plataforma
`offscreen` do Qt e não exigem sessão gráfica.

```
arca/
├── src/arca/
│   ├── core/          modelo, criptografia, formato, busca, auditoria
│   ├── services/      sessão de trabalho, trava de arquivo, CSV
│   ├── cli/           linha de comando
│   ├── gui/           interface gráfica (PySide6)
│   └── resources/     listas de palavras
├── tests/
└── docs/
```

## Licença

MIT. Veja [LICENSE](LICENSE).
