# Modelo de ameaças

Um gerenciador de senhas que promete proteger contra tudo não protege contra
nada, porque o usuário não sabe onde parar de confiar. Este documento delimita
o que o Arca defende, o que ele não defende e por quê.

## 1. O que está sendo protegido

O conteúdo do arquivo `.arca`: títulos, usuários, senhas, endereços e notas.
A estrutura de grupos e o número de entradas também ficam cifrados. **Não** ficam protegidos: o tamanho
aproximado do cofre, a data de modificação do arquivo e os parâmetros
criptográficos escolhidos, todos visíveis no cabeçalho em claro.

## 2. Ameaças cobertas

### 2.1 Roubo do arquivo

Alguém obtém uma cópia do `.arca` — backup em nuvem, pendrive perdido, disco
descartado.

O conteúdo está cifrado com AES-256 ou ChaCha20 sob uma chave derivada por
Argon2id. Com os parâmetros padrão (64 MiB, 4 iterações, 4 threads), cada
tentativa de senha custa cerca de meio segundo em uma CPU de mesa, e o custo
de memória impede que uma GPU compense isso com paralelismo barato.

A defesa vale exatamente o que valer a senha mestra. Uma frase-senha de seis
palavras da lista embutida dá 54 bits; uma senha de dicionário dá menos de 20.
Contra a segunda, nenhum KDF salva.

### 2.2 Adulteração do arquivo

Alguém com acesso de escrita altera o cofre — troca de bytes no corpo,
rebaixamento dos parâmetros do KDF para acelerar um ataque, reordenação ou
remoção de blocos, truncamento.

Todo o corpo é autenticado por HMAC-SHA256 em blocos, com subchave derivada do
índice de cada bloco, e o cabeçalho tem HMAC próprio. Qualquer uma dessas
alterações é detectada antes de o conteúdo ser decifrado. Detectar não é
recuperar: o Arca recusa o arquivo e o usuário recorre ao `.arca.bak` ou ao
seu backup.

### 2.3 Perda de dados por interrupção

Queda de energia ou encerramento forçado durante a gravação.

A gravação é atômica: arquivo temporário no mesmo diretório, `fsync`,
substituição por `os.replace`. Uma interrupção deixa o cofre anterior intacto.
O estado imediatamente anterior fica também em `.arca.bak`.

### 2.4 Vazamento pela área de transferência

A senha copiada permanece disponível a qualquer processo, e gerenciadores de
histórico de transferência a guardam indefinidamente.

A interface limpa a área de transferência 20 segundos depois da cópia, e só
limpa se o conteúdo ainda for o que ela colocou lá. Isso reduz a janela;
não a fecha.

### 2.5 Acesso oportunista à máquina destravada

Alguém se senta ao computador com o Arca aberto.

Trancar o cofre (`Ctrl+L`) descarta modelo, chaves e credenciais de uma vez.
Senhas nunca aparecem na tela sem uma ação explícita, e a busca não pesquisa
dentro de senhas — permitir isso daria a quem estiver de passagem uma forma
de confirmar palpites sem nada aparecer na tela.

O bloqueio automático por inatividade foi removido junto com as demais
funcionalidades acessórias: trancar é uma ação do usuário.

## 3. Ameaças não cobertas

### 3.1 Malware com privilégios do usuário

Um programa executando com a sua conta pode registrar o teclado, ler a memória
do processo Arca ou simplesmente copiar o cofre e esperar você digitar a senha.
Nenhum gerenciador de senhas em espaço de usuário resolve isso. `ProtectedValue`
e `SecretBytes` reduzem a chance de uma senha ser encontrada por varredura
ingênua de memória, mas não são obstáculo para um atacante com depurador.

### 3.2 Segredos residuais em memória

CPython não permite apagar de forma confiável objetos `bytes` e `str`: são
imutáveis e o interpretador pode copiá-los durante realocação de buffers ou
coleta de lixo. `SecretBytes` sobrescreve o `bytearray` que controla, e
`ProtectedValue` mantém os campos mascarados por um keystream sorteado a cada
execução, mas cópias transitórias podem sobreviver — inclusive em arquivo de
paginação. A mitigação real é cifrar o disco inteiro.

### 3.3 Análise de tráfego local e canais laterais

O Arca não faz medidas de tempo constante além das já oferecidas pelas
bibliotecas usadas (`hmac.compare_digest`, `secrets.compare_digest`). Um
atacante com medição precisa no mesmo host está fora do escopo.

### 3.4 Senha mestra fraca

É o ponto único de falha e não há defesa técnica contra ele. O que existe é
retorno honesto: o estimador classifica a senha na hora de defini-la, exibe a
entropia em bits e o tempo de busca exaustiva, e exige confirmação explícita
para prosseguir com uma senha fraca.

### 3.5 Perda da senha mestra

Perder a senha mestra significa perder o cofre. Não há recuperação, backdoor ou pergunta de
segurança — a existência de qualquer uma delas seria exatamente a brecha que o
projeto tenta não ter.

## 4. Escolhas criptográficas e o porquê

| Decisão                          | Motivo                                                                 |
|----------------------------------|------------------------------------------------------------------------|
| Argon2id como KDF                | vencedor da PHC; custo de memória encarece ataque em GPU/FPGA          |
| Parâmetros gravados no cofre     | permite elevar o custo depois sem quebrar cofres antigos               |
| Sal e IV novos a cada gravação   | chave de cifragem nunca se repete; elimina reúso de nonce no ChaCha20  |
| Encrypt-then-MAC                 | integridade verificável antes de expor a cifra a dados hostis          |
| HMAC por bloco com subchave      | detecta reordenação, duplicação e truncamento, não só alteração        |
| Domínios `0x01`/`0x02`           | separa chave de cifragem da semente de HMAC                            |
| Byte de presença de fator        | evita que arranjos distintos de fator colidam na chave composta        |
| Keystream sobre as senhas        | payload em memória e em `.bak` não expõe senhas em texto claro         |
| `secrets`, nunca `random`        | o Mersenne Twister é previsível a partir de poucas centenas de saídas  |

## 5. Premissas

1. O sistema operacional e o hardware não estão comprometidos.
2. O gerador de números aleatórios do sistema (`os.urandom`) é confiável.
3. As primitivas de `cryptography` e `argon2-cffi` estão corretas.
4. O usuário guarda uma cópia de segurança do cofre em local separado.
5. Não há comunicação de rede: o Arca nunca abre um socket, nem para
   verificação de vazamentos, nem para atualização, nem para telemetria.
