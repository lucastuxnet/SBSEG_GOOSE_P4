# Detecção de Ataques GOOSE com P4

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![P4](https://img.shields.io/badge/P4-16-red.svg)](https://p4.org/)
[![Fedora](https://img.shields.io/badge/Fedora-41-blue.svg)](https://fedoraproject.org/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-orange.svg)](https://ubuntu.com/)

Sistema de Detecção de Intrusão (IDS) para o protocolo **GOOSE (IEC 61850)** implementado em **P4**, executado no switch virtual **BMv2** (behavioral-model). O sistema identifica ataques em tempo real diretamente no plano de dados, sem necessidade de enviar tráfego para um controlador externo.

---

## 📋 Tabela de Conteúdos

- [Visão Geral](#visão-geral)
- [Arquitetura](#arquitetura)
- [Pré-requisitos](#pré-requisitos)
- [Instalação das Dependências](#instalação-das-dependências)
  - [Fedora](#fedora)
  - [Ubuntu](#ubuntu)
- [Configuração do Ambiente](#configuração-do-ambiente)
- [Estrutura do Repositório](#estrutura-do-repositório)
- [Guia de Uso](#guia-de-uso)
  - [1. Compilar o Programa P4](#1-compilar-o-programa-p4)
  - [2. Configurar Interfaces Virtuais](#2-configurar-interfaces-virtuais)
  - [3. Executar o Switch BMv2](#3-executar-o-switch-bmv2)
  - [4. Converter Regras para JSON](#4-converter-regras-para-json)
  - [5. Executar Testes de Ataque](#5-executar-testes-de-ataque)
- [Arquivos Gerados](#arquivos-gerados)
- [Resultados Esperados](#resultados-esperados)
- [Solução de Problemas](#solução-de-problemas)
- [Citação](#citação)
- [Licença](#licença)

---

## Visão Geral

Os sistemas de automação de subestações elétricas utilizam o protocolo **GOOSE (Generic Object Oriented Substation Event)** para comunicação em tempo real. Porém, esse protocolo foi projetado sem mecanismos de segurança nativos, tornando-se vulnerável a ataques como:

- **Injeção de mensagens** (masquerade)
- **Replay attacks**
- **Negação de serviço (DoS)**
- **Grayhole**

Este projeto implementa regras de detecção diretamente no **plano de dados** usando a linguagem **P4**, executadas no switch virtual **BMv2**, garantindo baixa latência e alta vazão.

---

## Arquitetura

┌─────────────────┐      ┌──────────────────┐      ┌───────────────────┐
│ Tráfego GOOSE   │────▶│ Switch BMv2      │────▶│ Regras P4         │
│ (veth pairs)    │      │ (simple_switch)  │      │ (detecção)        │
└─────────────────┘      └──────────────────┘      └───────────────────┘
│
▼
┌──────────────────┐
│ Logs de Ataque   │
│ (arquivos .log)  │
└──────────────────┘


---

## Pré-requisitos

| Componente          | Versão Mínima | Observação                          |
|---------------------|---------------|-------------------------------------|
| **Linux**           | Fedora 41 / Ubuntu 24.04 | Testado nestas distribuições |
| **Python**          | 3.8+          | Para scripts de teste e conversão   |
| **Scapy**           | 2.5+          | Geração de tráfego GOOSE            |
| **P4 Compiler**     | p4c-bm2-ss    | Compila P4 para BMv2                |
| **BMv2**            | simple_switch | Switch virtual da P4.org            |
| **PI** (P4Runtime)  | Última versão | Opcional para controle remoto       |

---

## Instalação das Dependências

## Fedora


### Atualizar sistema
```bash
sudo dnf update -y
```
### Instalar dependências básicas
```
sudo dnf install -y git make automake gcc gcc-c++ boost-devel \
    libpcap-devel libtool python3-devel python3-pip
```
### Instalar Python e Scapy
```
sudo dnf install -y python3-scapy
```
### Instalar pip e dependências Python
```
python3 -m pip install --user scapy numpy pandas
```


# Instalar P4 Compiler (p4c)

```
cd ~
git clone https://github.com/p4lang/p4c.git
cd p4c
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

# Instalar Behavioral Model (BMv2)

```
cd ~
git clone https://github.com/p4lang/behavioral-model.git
cd behavioral-model
./autogen.sh
./configure
make -j$(nproc)
sudo make install
```

# Instalar PI (P4Runtime)

```
cd ~
git clone https://github.com/p4lang/PI.git
cd PI
./autogen.sh
./configure
make -j$(nproc)
sudo make install
sudo ldconfig
```
---

---

## Ubuntu (24.04 ou superior)

### Atualizar sistema
```
sudo apt update && sudo apt upgrade -y
```

### Instalar dependências básicas
```
sudo apt install -y git make automake gcc g++ libboost-dev \
    libpcap-dev libtool python3-dev python3-pip
```
### Instalar Python e Scapy
```
sudo apt install -y python3-scapy
```

### Instalar pip e dependências
```
python3 -m pip install --user scapy numpy pandas
```

### Instalar P4 Compiler (p4c)
```
cd ~
git clone https://github.com/p4lang/p4c.git
cd p4c
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```


### Instalar Behavioral Model (BMv2)
```
cd ~
git clone https://github.com/p4lang/behavioral-model.git
cd behavioral-model
./autogen.sh
./configure
make -j$(nproc)
sudo make install
```


### Instalar PI (P4Runtime)
```
cd ~
git clone https://github.com/p4lang/PI.git
cd PI
./autogen.sh
./configure
make -j$(nproc)
sudo make install
sudo ldconfig
```
Observação: Tempo de instalação: O processo completo leva de 20 a 40 minutos dependendo da máquina.
---

## Configuração do Ambiente

```bash
# Clonar o repositório
git clone https://github.com/lucastuxnet/SBSEC_GOOSE_P4.git
cd SBSEC_GOOSE_P4

# Criar ambiente virtual Python (recomendado)
python3 -m venv .venv
source .venv/bin/activate

# Instalar dependências Python adicionais
pip install --upgrade pip
pip install scapy numpy pandas

```
---
## Estrutura do Repositório

SBSEC_GOOSE_P4/
├── behavioral-model/          # BMv2 source (Git LFS)
├── p4c/                       # P4 compiler source (Git LFS)
├── PI/                        # P4Runtime source (Git LFS)
├── goose_ids_complete.p4      # Programa P4 principal
├── goose_ids.json             # JSON compilado para BMv2
├── testar_ataques.py          # Script de teste básico
├── testar_ataques_log.py      # Script com logging detalhado
├── convert_p4.py              # Conversor de regras
├── veth.py                    # Criação de interfaces virtuais
├── logs/                      # Diretório de logs gerados do simulador por timestamp
├── README.md                  # Este arquivo
└── SETUP_GUIDE.md             # Guia detalhado de instalação

---

Guia de Uso
