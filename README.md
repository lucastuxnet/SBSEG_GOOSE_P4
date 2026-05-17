# 🛡️ Detecção de Ataques GOOSE com P4

> Sistema de Detecção de Intrusão (IDS) baseado em P4 para redes elétricas inteligentes, com suporte à detecção de ataques ao protocolo GOOSE (IEC 61850).

[![GitHub](https://img.shields.io/badge/GitHub-SBSEG__GOOSE__P4-blue?logo=github)](https://github.com/lucastuxnet/SBSEG_GOOSE_P4)
[![Python](https://img.shields.io/badge/Python-3.8%2B-yellow?logo=python)](https://python.org)
[![P4](https://img.shields.io/badge/P4-p4--16-green)](https://p4.org)
[![Version](https://img.shields.io/badge/versão-1.1.0-orange)](CHANGELOG.md)
[![Changelog](https://img.shields.io/badge/changelog-keep%20a%20changelog-lightgrey)](CHANGELOG.md)

---

## 📋 Pré-requisitos

| Componente | Versão |
|---|---|
| Sistema Operacional | Fedora Linux (testado) / Ubuntu |
| Python | 3.8+ |
| Scapy | Última estável |
| P4 Compiler | p4c-bm2-ss |
| BMv2 | simple_switch |

---

## ⚙️ Instalação das Dependências

### p4c — Compilador P4

O `p4c` é o compilador de referência para a linguagem P4. Ele traduz programas `.p4` para diferentes backends, incluindo o BMv2.

#### Ubuntu / Debian

```bash
# Adicionar repositório oficial p4lang
echo "deb http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_22.04/ /" \
  | sudo tee /etc/apt/sources.list.d/home:p4lang.list

curl -fsSL https://download.opensuse.org/repositories/home:/p4lang/xUbuntu_22.04/Release.key \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_p4lang.gpg > /dev/null

sudo apt-get update
sudo apt-get install -y p4lang-p4c
```

#### Fedora / RHEL

```bash
# Instalar dependências de build
sudo dnf install -y git cmake python3 python3-pip \
  boost-devel libfl-devel bison flex \
  libpcap-devel libevent-devel \
  python3-setuptools python3-ipaddr \
  openssl-devel

# Clonar e compilar p4c
git clone --recursive https://github.com/p4lang/p4c.git
cd p4c
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo make install
```

---

### behavioral-model (BMv2) — `simple_switch`

O BMv2 é o switch de referência para execução de programas P4 em software.

#### Ubuntu / Debian

```bash
sudo apt-get install -y p4lang-bmv2
```

Ou compilar a partir do fonte:

```bash
# Dependências
sudo apt-get install -y automake cmake libjudy-dev libgmp-dev \
  libpcap-dev libboost-dev libboost-test-dev libboost-program-options-dev \
  libboost-filesystem-dev libboost-log-dev libevent-dev libtool flex \
  bison pkg-config g++ libssl-dev

git clone https://github.com/p4lang/behavioral-model.git
cd behavioral-model
./install_deps.sh
./autogen.sh
./configure
make -j$(nproc)
sudo make install
```

#### Fedora / RHEL

```bash
# Dependências
sudo dnf install -y automake libtool boost-devel \
  boost-filesystem boost-program-options boost-log \
  libpcap-devel openssl-devel libevent-devel \
  python3-devel bison flex

git clone https://github.com/p4lang/behavioral-model.git
cd behavioral-model
./autogen.sh
./configure
make -j$(nproc)
sudo make install
```

---

### PI — Protocol Independent Interface

O PI é a camada de controle que permite comunicação entre o plano de controle e o `simple_switch`.

#### Ubuntu / Debian

```bash
# Dependências
sudo apt-get install -y libreadline-dev valgrind libtool-bin \
  libboost-dev libboost-system-dev libboost-thread-dev \
  libjudy-dev libgmp-dev pkg-config

git clone https://github.com/p4lang/PI.git
cd PI
git submodule update --init --recursive
./autogen.sh
./configure --with-proto
make -j$(nproc)
sudo make install
sudo ldconfig
```

#### Fedora / RHEL

```bash
# Dependências
sudo dnf install -y readline-devel libtool boost-devel \
  boost-system boost-thread Judy-devel gmp-devel pkgconf

git clone https://github.com/p4lang/PI.git
cd PI
git submodule update --init --recursive
./autogen.sh
./configure --with-proto
make -j$(nproc)
sudo make install
sudo ldconfig
```

---

## 🚀 Modo de Uso

### 1. Clonar o Repositório

```bash
git clone https://github.com/lucastuxnet/SBSEG_GOOSE_P4.git
cd SBSEG_GOOSE_P4
```

### 2. Criar e Ativar o Ambiente Virtual

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Criar Interfaces Virtuais

```bash
sudo python veth.py
# Nota: não é necessário adicionar IPs às interfaces
```

---

## 🔧 Passo a Passo — Compilar e Executar

### Passo 1: Compilar o Programa P4

```bash
p4c-bm2-ss --std p4-16 -o goose_ids_complete.json goose_ids_complete.p4
```

### Passo 2: Iniciar o Simple Switch

```bash
LOG_FILE="switch.log"

sudo simple_switch \
  --log-console \
  -i 0@veth0 \
  -i 1@veth2 \
  goose_detection.json 2>&1 | tee "$LOG_FILE"
```

---

## 🔁 Utilizando o Conversor de Regras (rules.py)

> ⚠️ O arquivo `rules.py` foi gerado utilizando a ferramenta desenvolvida no trabalho [**SBRC 2026**](https://github.com/lucastuxnet/SBSEG_2026). Essa ferramenta permite definir regras de detecção em alto nível que são automaticamente convertidas para código P4 compatível com o BMv2.

### Passo 1: Ativar o Ambiente Virtual

```bash
source .venv/bin/activate
```

### Passo 2: Converter as Regras para P4

```bash
python convert_p4.py rules.py -o regras.p4
```

### Passo 3: Compilar o Arquivo P4 Gerado

```bash
p4c-bm2-ss --std p4-16 -o goose_convert.json regras.p4
```

### Passo 4: Executar os Testes de Ataque

```bash
sudo python testar_ataques_log.py goose_convert.json
```

---

## 📁 Estrutura do Projeto

```
SBSEG_GOOSE_P4/
├── goose_ids_complete.p4     # Programa P4 principal
├── goose_detection.json      # Bytecode BMv2 gerado
├── rules.py                  # Regras de detecção (geradas via SBRC 2026)
├── convert_p4.py             # Conversor de regras para P4
├── testar_ataques_log.py     # Script de simulação de ataques
├── veth.py                   # Configuração de interfaces virtuais
├── requirements.txt          # Dependências Python
├── CHANGELOG.md              # Histórico de versões
└── logs/                     # Relatórios e logs gerados automaticamente
    ├── test_completo_*.log
    ├── relatorio_*.json
    └── relatorio_*.html
```

---

## 📝 Changelog

Veja o arquivo [CHANGELOG.md](CHANGELOG.md) para o histórico completo de versões e mudanças.

| Versão | Data | Destaque |
|---|---|---|
| [1.1.0](CHANGELOG.md#110---2026-05-15) | 2026-05-15 | Conversor `rules.py` → P4, relatórios HTML/JSON, integração SBRC 2026 |
| [1.0.0](CHANGELOG.md#100---2026-05-14) | 2026-05-14 | Lançamento inicial — 21 regras de detecção GOOSE em P4 |

---

## 🔗 Referências

- 📦 **Este projeto:** [SBSEC_GOOSE_P4](https://github.com/lucastuxnet/SBSEG_GOOSE_P4)
- 🛠️ **Ferramenta de criação de regras:** [SBRC_2026](https://github.com/lucastuxnet/SBRG_2026)
- 📖 **p4lang/p4c:** https://github.com/p4lang/p4c
- 📖 **p4lang/behavioral-model:** https://github.com/p4lang/behavioral-model
- 📖 **p4lang/PI:** https://github.com/p4lang/PI

---

## 📄 Licença

Este projeto está licenciado sob os termos da licença MIT. Consulte o arquivo `LICENSE` para mais detalhes.
