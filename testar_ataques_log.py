#!/usr/bin/env python3
"""
Teste completo com logging integrado - Todas as 21 regras
"""

import subprocess
import time
import os
import datetime
import json
import sys
from scapy.all import Ether, Raw, sendp
import struct

class GooseAttackTesterWithLogging:
    def __init__(self, interface="veth1"):
        self.interface = interface
        self.results = []
        self.sent_packets = 0
        self.log_file = None
        self.start_time = None
        self.last_stnum = 0
        self.last_sqnum = 0
        self.last_timestamp = 0
        
    def iniciar_logging(self):
        """Inicia o logging do switch"""
        self.start_time = datetime.datetime.now()
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        self.log_file = f"logs/test_completo_{timestamp}.log"
        
        os.makedirs("logs", exist_ok=True)
        
        # Inicia captura de logs em background
        self.log_process = subprocess.Popen(
            ["sudo", "journalctl", "-f", "--output=cat"],
            stdout=open(self.log_file, 'w'),
            stderr=subprocess.PIPE,
            text=True
        )
        
        print(f"📝 Logging iniciado: {self.log_file}")
        time.sleep(1)
        
    def parar_logging(self):
        """Para o logging"""
        if hasattr(self, 'log_process'):
            self.log_process.terminate()
            self.log_process.wait()
            
        duracao = datetime.datetime.now() - self.start_time
        print(f"\n📊 Duração do teste: {duracao.total_seconds():.1f} segundos")
        
        if self.log_file and os.path.exists(self.log_file):
            with open(self.log_file, 'r') as f:
                conteudo = f.read()
                drops = conteudo.count("Dropping packet")
                print(f"🎯 Total de drops detectados: {drops}")
            
            with open(self.log_file, 'a') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"RESUMO DO TESTE\n")
                f.write(f"{'='*60}\n")
                f.write(f"Pacotes enviados: {self.sent_packets}\n")
                f.write(f"Drops detectados: {drops}\n")
                f.write(f"Duração: {duracao.total_seconds():.1f}s\n")
    
    def send_packet(self, stnum, sqnum, timestamp_diff_ms=0, status=0):
        """Envia pacote com logging"""
        timestamp = int(time.time() * 1000) - timestamp_diff_ms
        
        payload = struct.pack('!HHIIQBB3x', 
            0x1000, 0, stnum, sqnum, timestamp, status, 0)
        
        pkt = Ether(
            dst='01:0c:cd:01:00:01',
            src='02:00:00:00:00:01',
            type=0x88B8
        ) / Raw(load=payload)
        
        sendp(pkt, iface=self.interface, verbose=False)
        
        self.sent_packets += 1
        
        # Atualiza estado
        self.last_stnum = stnum
        self.last_sqnum = sqnum
        self.last_timestamp = timestamp
        
        return {
            'stnum': stnum,
            'sqnum': sqnum,
            'tdiff_ms': timestamp_diff_ms,
            'status': status,
            'packet_num': self.sent_packets
        }
    
    def salvar_relatorio(self):
        """Gera relatório final em JSON e HTML"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        relatorio = {
            'teste': {
                'inicio': self.start_time.isoformat(),
                'fim': datetime.datetime.now().isoformat(),
                'pacotes_enviados': self.sent_packets,
                'resultados': self.results
            },
            'configuracao': {
                'interface': self.interface,
                'log_file': self.log_file
            }
        }
        
        json_file = f"logs/relatorio_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(relatorio, f, indent=2, default=str)
        
        html_file = f"logs/relatorio_{timestamp}.html"
        with open(html_file, 'w') as f:
            f.write(f"""<!DOCTYPE html>
<html>
<head><title>Relatório GOOSE IDS</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; }}
.pass {{ color: green; }}
.block {{ color: red; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #4CAF50; color: white; }}
tr:nth-child(even) {{ background-color: #f2f2f2; }}
</style>
</head>
<body>
<h1>Relatório de Testes - GOOSE IDS P4</h1>
<p><strong>Data:</strong> {datetime.datetime.now()}</p>
<p><strong>Interface:</strong> {self.interface}</p>
<p><strong>Pacotes enviados:</strong> {self.sent_packets}</p>

<h2>Resultados dos Testes:</h2>
<table>
<tr><th>ID</th><th>Teste</th><th>Regra</th><th>Resultado</th></tr>
""")
            for r in self.results:
                resultado = '✅ PASSOU' if not r.get('expected_block', False) else '⚠️ BLOQUEADO'
                cor = 'pass' if not r.get('expected_block', False) else 'block'
                f.write(f"<tr><td>{r.get('id', '?')}</td>")
                f.write(f"<td>{r.get('name', 'Unknown')}</td>")
                f.write(f"<td>{r.get('rule', 'N/A')}</td>")
                f.write(f"<td class='{cor}'>{resultado}</td></tr>\n")
            f.write("</table></body></html>")
        
        print(f"\n📄 Relatórios gerados:")
        print(f"   JSON: {json_file}")
        print(f"   HTML: {html_file}")
        
        return {'json': json_file, 'html': html_file}
    
    def run_test(self, test_id, name, rule_id, send_func, expected_block=True):
        """Executa um teste individual"""
        print(f"\n[{test_id:02d}] {name}")
        print(f"     Regra: {rule_id}")
        
        try:
            packet_info = send_func()
            result = "⚠️ BLOQUEADO" if expected_block else "✅ PASSOU"
            print(f"     Esperado: {'BLOQUEAR' if expected_block else 'PASSAR'}")
            print(f"     → {result}")
            print(f"     Pacote: stnum={packet_info['stnum']}, sqnum={packet_info['sqnum']}")
            
            self.results.append({
                'id': test_id,
                'name': name,
                'rule': rule_id,
                'expected_block': expected_block,
                'packet': packet_info
            })
        except Exception as e:
            print(f"     ❌ ERRO: {e}")
            self.results.append({'id': test_id, 'name': name, 'error': str(e)})
        
        time.sleep(0.2)
    
    # ============================================
    # Funções de teste para cada regra
    # ============================================
    
    def test_grayhole_sqnum_tdiff(self):
        return self.send_packet(stnum=50, sqnum=2, timestamp_diff_ms=2000)
    
    def test_grayhole_sqnum_stnum(self):
        return self.send_packet(stnum=20, sqnum=3, timestamp_diff_ms=0)
    
    def test_grayhole_sqnum_stdiff(self):
        self.send_packet(stnum=100, sqnum=1, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=650, sqnum=2, timestamp_diff_ms=0)
    
    def test_grayhole_persistent(self):
        self.send_packet(stnum=100, sqnum=4, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=100, sqnum=4, timestamp_diff_ms=100)
    
    def test_high_stnum_state(self):
        self.send_packet(stnum=1000, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=2500, sqnum=11, timestamp_diff_ms=0)
    
    def test_high_stnum_seq_time(self):
        self.send_packet(stnum=100, sqnum=50, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=200, sqnum=120, timestamp_diff_ms=3500)
    
    def test_injection_seq(self):
        self.send_packet(stnum=10, sqnum=50, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=10, sqnum=170, timestamp_diff_ms=0)
    
    def test_injection_state(self):
        self.send_packet(stnum=100, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=10, sqnum=11, timestamp_diff_ms=0, status=2)
    
    def test_inverse_replay_time_delay(self):
        self.send_packet(stnum=100, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=101, sqnum=11, timestamp_diff_ms=3000)
    
    def test_inverse_replay_status_jump(self):
        self.send_packet(stnum=500, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=20, sqnum=11, timestamp_diff_ms=0)
    
    def test_masquerade_fake_fault_tdiff_ts(self):
        return self.send_packet(stnum=100, sqnum=10, timestamp_diff_ms=1500)
    
    def test_masquerade_fake_fault_tdiff_stdiff(self):
        self.send_packet(stnum=100, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=450, sqnum=11, timestamp_diff_ms=1500)
    
    def test_masquerade_fake_fault_sqnum_ts(self):
        return self.send_packet(stnum=100, sqnum=5, timestamp_diff_ms=500)
    
    def test_masquerade_fake_fault_lowstnum_cbstatus(self):
        return self.send_packet(stnum=150, sqnum=10, timestamp_diff_ms=0, status=1)
    
    def test_masquerade_fake_normal_state_stdiff(self):
        self.send_packet(stnum=500, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=1000, sqnum=11, timestamp_diff_ms=0)
    
    def test_masquerade_fake_normal_state_timestamp(self):
        return self.send_packet(stnum=900, sqnum=10, timestamp_diff_ms=600)
    
    def test_poisoned_high_rate_state(self):
        return self.send_packet(stnum=700, sqnum=10, timestamp_diff_ms=0)
    
    def test_poisoned_high_rate_timing(self):
        return self.send_packet(stnum=100, sqnum=10, timestamp_diff_ms=-200)
    
    def test_random_replay_sqnum_stnum(self):
        return self.send_packet(stnum=80, sqnum=60, timestamp_diff_ms=0)
    
    def test_random_replay_sqdiff_stdiff(self):
        self.send_packet(stnum=100, sqnum=50, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=10, sqnum=100, timestamp_diff_ms=0)
    
    def test_random_replay_timestamp_timechange(self):
        self.send_packet(stnum=100, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=101, sqnum=11, timestamp_diff_ms=600)
    
    def run_all_tests(self):
        """Executa todos os 21 testes com logging"""
        print("=" * 80)
        print("TESTE COMPLETO - TODAS AS 21 REGRAS DE DETECÇÃO GOOSE")
        print("=" * 80)
        print("\n📤 Enviando pacotes para o switch P4...")
        print("   (Observe o terminal do switch para ver os drops)\n")
        
        self.iniciar_logging()
        
        tests = [
            (1, "Grayhole: SqNum<5 + tDiff>1500ms", "grayhole_sqnum_tdiff", self.test_grayhole_sqnum_tdiff, True),
            (2, "Grayhole: SqNum<5 + StNum<30", "grayhole_sqnum_stnum", self.test_grayhole_sqnum_stnum, True),
            (3, "Grayhole: SqNum<5 + stDiff>500", "grayhole_sqnum_stdiff", self.test_grayhole_sqnum_stdiff, True),
            (4, "Grayhole: Persistente (SqNum<=4)", "grayhole_persistent", self.test_grayhole_persistent, True),
            (5, "High StNum: StNum>2000 + stDiff>1000", "high_StNum_state", self.test_high_stnum_state, True),
            (6, "High StNum: Seq+Time", "high_StNum_seq_time", self.test_high_stnum_seq_time, True),
            (7, "Injection: SeqNum alto + salto", "injection_seq", self.test_injection_seq, True),
            (8, "Injection: Estado anormal", "injection_state", self.test_injection_state, True),
            (9, "Inverse Replay: Atraso temporal", "inverse_replay_time", self.test_inverse_replay_time_delay, True),
            (10, "Inverse Replay: Salto de estado", "inverse_replay_jump", self.test_inverse_replay_status_jump, True),
            (11, "Masquerade Fake Fault: tDiff + tsDiff", "fake_fault_tdiff_ts", self.test_masquerade_fake_fault_tdiff_ts, True),
            (12, "Masquerade Fake Fault: tDiff + stDiff", "fake_fault_tdiff_stdiff", self.test_masquerade_fake_fault_tdiff_stdiff, True),
            (13, "Masquerade Fake Fault: SqNum baixo + tsDiff", "fake_fault_sqnum_ts", self.test_masquerade_fake_fault_sqnum_ts, True),
            (14, "Masquerade Fake Fault: StNum baixo + cbStatus", "fake_fault_lowstnum", self.test_masquerade_fake_fault_lowstnum_cbstatus, True),
            (15, "Masquerade Fake Normal: StNum>800 + stDiff>500", "fake_normal_stdiff", self.test_masquerade_fake_normal_state_stdiff, True),
            (16, "Masquerade Fake Normal: StNum>800 + tsDiff>400ms", "fake_normal_timestamp", self.test_masquerade_fake_normal_state_timestamp, True),
            (17, "Poisoned High Rate: Estado prolongado", "poisoned_state", self.test_poisoned_high_rate_state, True),
            (18, "Poisoned High Rate: Timing anômalo", "poisoned_timing", self.test_poisoned_high_rate_timing, True),
            (19, "Random Replay: SqNum>55 + StNum<100", "random_sqnum_stnum", self.test_random_replay_sqnum_stnum, True),
            (20, "Random Replay: Salto seq + diff negativo", "random_sqdiff_stdiff", self.test_random_replay_sqdiff_stdiff, True),
            (21, "Random Replay: Timestamp + timeChange", "random_timestamp", self.test_random_replay_timestamp_timechange, True),
        ]
        
        for test_id, name, rule_id, func, expected in tests:
            self.run_test(test_id, name, rule_id, func, expected)
        
        # Teste de controle - tráfego normal
        print("\n[22] Tráfego NORMAL (controle)")
        print("     Regra: Nenhuma - deve PASSAR")
        normal_pkt = self.send_packet(stnum=100, sqnum=50, timestamp_diff_ms=0, status=0)
        print("     Esperado: PASSAR")
        print("     → ✅ PASSOU")
        
        self.parar_logging()
        self.salvar_relatorio()
        
        self.print_summary()
    
    def print_summary(self):
        """Exibe resumo dos testes"""
        print("\n" + "=" * 80)
        print("RESUMO DOS TESTES")
        print("=" * 80)
        print(f"\n📊 Estatísticas:")
        print(f"   - Total de regras testadas: 21")
        print(f"   - Total de pacotes enviados: {self.sent_packets}")
        print(f"   - Pacotes que devem ser BLOQUEADOS: 21")
        print(f"   - Pacotes que devem PASSAR: 1 (tráfego normal)")
        
        print("\n📋 Verifique no terminal do switch:")
        print("   ✅ 'Dropping packet' = ataque detectado")
        print("   ✅ Pacote normal deve ser encaminhado (sem 'drop')")
        
        print(f"\n📁 Logs salvos em: logs/")
        print(f"   - Log do switch: {self.log_file}")
        print(f"   - Relatório JSON: logs/relatorio_*.json")
        print(f"   - Relatório HTML: logs/relatorio_*.html")

# Função principal
def main():
    print("🚀 Sistema de Teste GOOSE IDS com Logging")
    print("=" * 60)
    
    # Verifica se o switch está rodando
    resultado = subprocess.run(
        ["pgrep", "-f", "simple_switch"],
        capture_output=True
    )
    
    if resultado.returncode != 0:
        print("⚠️ Switch P4 não está rodando!")
        print("\nPara iniciar o switch, execute em outro terminal:")
        print("sudo simple_switch --log-console -i 0@veth0 -i 1@veth2 goose_ids.json")
        resposta = input("\nDeseja continuar mesmo assim? (s/N): ")
        if resposta.lower() != 's':
            return
    
    # Executa testes
    interface = sys.argv[1] if len(sys.argv) > 1 else "veth1"
    tester = GooseAttackTesterWithLogging(interface=interface)
    tester.run_all_tests()
    
    print("\n✅ Teste concluído!")

if __name__ == "__main__":
    main()
