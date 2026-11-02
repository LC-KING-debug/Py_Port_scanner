# LC_KING Port Scanner

Ferramenta desenvolvida em Python para análise de portas TCP e identificação de dispositivos conhecidos em uma rede local.

O projeto reúne funções de reconhecimento de IP, identificação de serviços, análise de portas abertas e geração de relatórios técnicos em JSON.

## Funcionalidades

- **Port Scanner:** escaneamento de portas TCP de um IP ou hostname.
- **Tipos de escaneamento:** portas comuns, Top 1000, todas as 65535 portas ou lista personalizada.
- **Informações de IP:** identificação de hostname, versão IP, subnet e broadcast.
- **IP local:** consulta do endereço IP do computador.
- **Gateway:** identificação do gateway padrão.
- **Dispositivos da rede:** consulta dos IPs conhecidos na tabela de vizinhos do sistema.
- **Identificação de serviços:** associação de portas abertas aos serviços TCP conhecidos.
- **Relatórios:** geração automática de relatórios em JSON.
- **Recomendações:** sugestões básicas de segurança conforme as portas identificadas.

## Tecnologias utilizadas

- Python 3
- Socket
- IPaddress
- ThreadPoolExecutor
- Subprocess
- JSON
- Expressões regulares

## Como executar

Clone o repositório:

```bash
git clone https://github.com/LC-KING-debug/Py_Port_scanner.git
```

Entre na pasta:

```bash
cd PyScanner
```

Execute o projeto:

```bash
python3 main.py
```

Não é necessário instalar bibliotecas externas, pois o projeto utiliza módulos da biblioteca padrão do Python.

## Relatórios

Após cada escaneamento, o programa gera automaticamente um relatório JSON dentro da pasta `reports/`.

Os relatórios armazenam informações como:

- Endereço IP analisado.
- Hostname identificado.
- Portas abertas.
- Serviços associados.
- Tempo de execução.
- Recomendações de segurança.

## Objetivo do projeto

Este projeto faz parte dos meus estudos em Python, redes de computadores e cibersegurança, com foco em análise de rede e segurança defensiva (Blue Team).

A ideia é desenvolver ferramentas próprias, compreender melhor o funcionamento das redes e aprimorar minhas habilidades em programação e análise técnica.

## Aviso de uso

Utilize a ferramenta somente em dispositivos e redes próprios ou em ambientes nos quais você tenha autorização para realizar testes.

**Desenvolvido por LC-KING | Cybersecurity & Blue Team**