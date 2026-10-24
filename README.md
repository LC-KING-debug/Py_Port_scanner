# LC_KING Port Scanner

Scanner TCP interativo que coleta informações básicas do endereço informado, exibe um relatório e salva os resultados em JSON.

## Funcionalidades

- Aceita um endereço IPv4 ou hostname e tenta resolvê-lo para IPv4.
- Consulta hostname por DNS reverso e informa características do IP, como versão, endereço privado/global e, para IPv4, rede `/24` e broadcast.
- Verifica portas TCP e identifica cada porta aberta usando primeiro o catálogo conhecido pela aplicação e, como alternativa, o cadastro de serviços TCP do sistema operacional.
- Exibe o número da porta, protocolo, nome associado ao serviço e estado. Se não houver nome cadastrado, informa `Sem serviço TCP cadastrado`.
- Gera resumo de portas associadas a serviços web, bancos de dados e administração, além de recomendações básicas.
- Identifica o sistema operacional local somente quando o endereço analisado é de loopback (`127.0.0.1` ou `::1`). Para outros endereços, o sistema operacional fica como não identificado.
- Salva cada relatório em `reports/`, em um arquivo JSON separado.
- Valida portas personalizadas e trata erros de resolução, cancelamento e gravação do relatório.
- Após cada tentativa, pergunta se deseja analisar outro IP; responda `s` ou `sim` para continuar. Qualquer outra resposta encerra o programa.

## Requisitos

- Python 3.8 ou superior.
- Não requer instalação de pacotes externos.
- A máquina precisa ter acesso à rede para consultar DNS e verificar os endereços autorizados.

## Como executar

Abra o terminal na pasta do projeto e execute um dos comandos:

Linux:

```bash
python3 main.py
```

macOS:

```bash
python3 main.py
```

Windows (Prompt de Comando ou PowerShell):

```powershell
py main.py
```

Informe um IP ou hostname quando solicitado. Pressione Enter para usar `127.0.0.1`.

## Modos de análise

1. Portas comuns: conjunto de portas de uso frequente definido pela aplicação.
2. Top 1000: portas TCP de `1` a `1000`.
3. Completo: portas TCP de `1` a `65535`; pode levar mais tempo.
4. Personalizado: lista separada por vírgulas, por exemplo `22,80,443,8080`. Os valores aceitos vão de `1` a `65535`.

## Relatórios

Após a análise, o terminal mostra o relatório e o programa cria automaticamente a pasta `reports/` se necessário. Os arquivos seguem o padrão:

```text
reports/scan_<data_hora>_<ip>.json
```

O JSON inclui os dados do alvo, características do IP, duração, quantidade de portas analisadas, portas abertas, nomes de serviços associados e recomendações.

## Como interpretar os resultados

O nome associado a uma porta vem de um catálogo conhecido ou do cadastro TCP disponível no sistema. É uma associação convencional, não uma confirmação do software que está executando no host. Uma porta sem cadastro pode aparecer como `Sem serviço TCP cadastrado`; isso não significa que a porta não tenha um serviço.

O scanner verifica somente TCP. O sistema operacional de um host remoto não é inferido. Execute análises apenas em máquinas e redes para as quais você tem autorização.