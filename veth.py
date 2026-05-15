#!/usr/bin/env python3

import subprocess
import sys
import re

class VethManager:
    def __init__(self):
        self.interfaces = ['veth0', 'veth1', 'veth2', 'veth3']
    
    def interface_exists(self, interface):
        """Verifica se uma interface já existe"""
        try:
            result = subprocess.run(f"ip link show {interface}", 
                                   shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def check_existing_interfaces(self):
        """Verifica se alguma interface já existe"""
        existing = [iface for iface in self.interfaces if self.interface_exists(iface)]
        if existing:
            print(f"⚠️  Atenção: As seguintes interfaces já existem: {', '.join(existing)}")
            resposta = input("Deseja removê-las e recriar? (s/N): ").lower()
            if resposta == 's':
                self.remove_interfaces(existing)
                return True
            else:
                print("❌ Operação cancelada.")
                return False
        return True
    
    def remove_interfaces(self, interfaces):
        """Remove interfaces existentes"""
        print(f"Removendo interfaces: {', '.join(interfaces)}")
        for iface in interfaces:
            subprocess.run(f"sudo ip link delete {iface}", 
                          shell=True, capture_output=True)
        print("✅ Interfaces removidas com sucesso!")
    
    def run_command(self, command, description):
        """Executa um comando e trata erros"""
        print(f"📌 {description}...")
        try:
            result = subprocess.run(command, shell=True, check=True,
                                   capture_output=True, text=True)
            print(f"   ✅ Sucesso: {command}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"   ❌ Erro: {e.stderr}")
            return False
    
    def create_veth_pair(self, name1, name2):
        """Cria um par veth"""
        return self.run_command(
            f"sudo ip link add name {name1} type veth peer name {name2}",
            f"Criando par veth {name1}/{name2}"
        )
    
    def set_interface_up(self, interface):
        """Ativa uma interface"""
        return self.run_command(
            f"sudo ip link set {interface} up",
            f"Ativando {interface}"
        )
    
    def create_all_interfaces(self):
        """Cria todas as interfaces veth"""
        print("\n🚀 Iniciando criação das interfaces veth...\n")
        
        # Criar pares veth
        if not self.create_veth_pair('veth0', 'veth1'):
            return False
        if not self.create_veth_pair('veth2', 'veth3'):
            return False
        
        # Ativar interfaces
        for iface in self.interfaces:
            if not self.set_interface_up(iface):
                return False
        
        return True
    
    def assign_ip_addresses(self):
        """Opcional: Atribui endereços IP às interfaces"""
        print("\n🌐 Deseja atribuir endereços IP? (s/N): ", end='')
        resposta = input().lower()
        
        if resposta == 's':
            ips = {
                'veth0': '10.0.1.1/24',
                'veth1': '10.0.1.2/24',
                'veth2': '10.0.2.1/24',
                'veth3': '10.0.2.2/24'
            }
            
            for iface, ip in ips.items():
                self.run_command(
                    f"sudo ip addr add {ip} dev {iface}",
                    f"Atribuindo IP {ip} à {iface}"
                )
    
    def show_status(self):
        """Mostra o status das interfaces"""
        print("\n📊 Status das interfaces:")
        subprocess.run("ip -br link show veth0 veth1 veth2 veth3", shell=True)
        
        print("\n📋 Endereços IP configurados:")
        subprocess.run("ip -4 addr show veth0 veth1 veth2 veth3 | grep -E '(veth[0-3]|inet )'", 
                      shell=True)

def main():
    manager = VethManager()
    
    # Verificar se está rodando com sudo
    try:
        subprocess.run("sudo -n true", shell=True, check=True, capture_output=True)
    except:
        print("❌ Este script precisa de permissões sudo para executar.")
        print("   Execute com: python3 script.py")
        print("   Ou garanta que seu usuário tem permissões sudo sem senha.")
        sys.exit(1)
    
    # Verificar interfaces existentes
    if not manager.check_existing_interfaces():
        sys.exit(1)
    
    # Criar interfaces
    if manager.create_all_interfaces():
        print("\n" + "="*50)
        print("✅ TODAS AS INTERFACES FORAM CRIADAS COM SUCESSO!")
        print("="*50)
        
        manager.show_status()
        
        # Opcional: atribuir IPs
        manager.assign_ip_addresses()
        
        print("\n💡 Dica: Para remover as interfaces, execute:")
        print("   sudo ip link delete veth0 && sudo ip link delete veth2")
    else:
        print("\n❌ Falha ao criar as interfaces.")
        sys.exit(1)

if __name__ == "__main__":
    main()
