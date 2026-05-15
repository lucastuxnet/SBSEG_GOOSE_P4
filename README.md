# Guia de Demonstração - Detecção de Ataques GOOSE com P4

## Pré-requisitos
- Fedora Linux (testado)
- Python 3.8+
- Scapy
- P4 compiler (p4c-bm2-ss)
- BMv2 (simple_switch)

## Passo 1: Compilar o Programa P4

```bash
p4c-bm2-ss --std p4-16 -o goose_ids_complete.json goose_ids_complete.p4
