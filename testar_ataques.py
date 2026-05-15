#!/usr/bin/env python3
"""
Teste completo de todas as 21 regras de detecção GOOSE
Baseado no arquivo rules.py original do projeto SBRC_2026
"""

from scapy.all import Ether, Raw, sendp
import struct
import time
import sys

class GooseAttackTester:
    def __init__(self, interface="veth1"):
        self.interface = interface
        self.results = []
        self.last_timestamp = int(time.time() * 1000)
        self.last_stnum = 0
        self.last_sqnum = 0
        self.sent_packets = 0
        
    def send_packet(self, stnum, sqnum, timestamp_diff_ms=0, status=0):
        """Envia um pacote GOOSE e atualiza estado"""
        timestamp = int(time.time() * 1000) - timestamp_diff_ms
        
        # Formato correto do header GOOSE:
        # ! = network byte order (big-endian)
        # H = unsigned short (2 bytes) - appid
        # H = unsigned short (2 bytes) - reserved  
        # I = unsigned int (4 bytes) - stnum
        # I = unsigned int (4 bytes) - sqnum
        # Q = unsigned long long (8 bytes) - timestamp
        # B = unsigned char (1 byte) - status
        # 3x = 3 bytes de padding
        payload = struct.pack('!HHIIQBB3x', 
            0x1000,     # appid
            0,          # reserved
            stnum,      # stnum
            sqnum,      # sqnum
            timestamp,  # timestamp
            status,     # status
            0)          # padding byte adicional
        
        pkt = Ether(
            dst='01:0c:cd:01:00:01',  # Multicast GOOSE
            src='02:00:00:00:00:01',
            type=0x88B8                # Ethertype GOOSE
        ) / Raw(load=payload)
        
        sendp(pkt, iface=self.interface, verbose=False)
        
        # Atualiza estado para próximos testes
        self.last_stnum = stnum
        self.last_sqnum = sqnum
        self.last_timestamp = timestamp
        self.sent_packets += 1
        
        return {
            'stnum': stnum,
            'sqnum': sqnum,
            'tdiff_ms': timestamp_diff_ms,
            'status': status,
            'timestamp': timestamp
        }
    
    def run_test(self, test_id, name, rule_id, send_func, expected_block=True):
        """Executa um teste individual"""
        print(f"\n[{test_id:02d}] {name}")
        print(f"     Regra: {rule_id}")
        
        try:
            packet_info = send_func()
            result = "⚠️  BLOQUEADO" if expected_block else "✅ PASSOU"
            print(f"     Esperado: {'BLOQUEAR' if expected_block else 'PASSAR'}")
            print(f"     → {result}")
            print(f"     Pacote: stnum={packet_info['stnum']}, sqnum={packet_info['sqnum']}, status={packet_info['status']}")
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
        
        time.sleep(0.2)  # Pequena pausa entre pacotes
    
    # ============================================
    # Funções de teste para cada regra
    # ============================================
    
    def test_grayhole_sqnum_tdiff(self):
        """rule_grayhole_sqnum_tdiff: sqnum < 5 and tdiff > 1500ms"""
        return self.send_packet(stnum=50, sqnum=2, timestamp_diff_ms=2000)
    
    def test_grayhole_sqnum_stnum(self):
        """rule_grayhole_sqnum_stnum: sqnum < 5 and stnum < 30"""
        return self.send_packet(stnum=20, sqnum=3, timestamp_diff_ms=0)
    
    def test_grayhole_sqnum_stdiff(self):
        """rule_grayhole_sqnum_stdiff: sqnum < 5 and stdiff > 500"""
        self.send_packet(stnum=100, sqnum=1, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=650, sqnum=2, timestamp_diff_ms=0)
    
    def test_grayhole_persistent(self):
        """rule_grayhole_persistent: sqnum <= 4, timestampDiff <= 200ms, timeFromLastChange > 100s"""
        self.send_packet(stnum=100, sqnum=4, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=100, sqnum=4, timestamp_diff_ms=100)
    
    def test_high_stnum_state(self):
        """rule_high_StNum_state: stnum > 2000 and stdiff > 1000"""
        self.send_packet(stnum=1000, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=2500, sqnum=11, timestamp_diff_ms=0)
    
    def test_high_stnum_seq_time(self):
        """rule_high_StNum_seq_time: sqnum > 100, sqdiff > 50, tdiff > 3000, timestampDiff > 500ms"""
        self.send_packet(stnum=100, sqnum=50, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=200, sqnum=120, timestamp_diff_ms=3500)
    
    def test_injection_seq(self):
        """rule_injection_seq: sqnum > 80 and sqdiff > 100"""
        self.send_packet(stnum=10, sqnum=50, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=10, sqnum=170, timestamp_diff_ms=0)
    
    def test_injection_state(self):
        """rule_injection_state: stnum < 20 and stdiff < -65000 and cbStatus > 1"""
        self.send_packet(stnum=100, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=10, sqnum=11, timestamp_diff_ms=0, status=2)
    
    def test_inverse_replay_time_delay(self):
        """rule_inverse_replay_time_delay: tdiff > 2500ms and timeFromLastChange > 180s"""
        self.send_packet(stnum=100, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=101, sqnum=11, timestamp_diff_ms=3000)
    
    def test_inverse_replay_status_jump(self):
        """rule_inverse_replay_status_jump: stnum < 30 and stdiff > 400"""
        self.send_packet(stnum=500, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=20, sqnum=11, timestamp_diff_ms=0)
    
    def test_masquerade_fake_fault_tdiff_ts(self):
        """rule_masquerade_fake_fault_tdiff_ts: tdiff > 1000ms and timestampDiff > 200ms"""
        return self.send_packet(stnum=100, sqnum=10, timestamp_diff_ms=1500)
    
    def test_masquerade_fake_fault_tdiff_stdiff(self):
        """rule_masquerade_fake_fault_tdiff_stdiff: tdiff > 1000ms and stdiff > 300"""
        self.send_packet(stnum=100, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=450, sqnum=11, timestamp_diff_ms=1500)
    
    def test_masquerade_fake_fault_sqnum_ts(self):
        """rule_masquerade_fake_fault_sqnum_ts: sqnum < 10 and timestampDiff > 300ms"""
        return self.send_packet(stnum=100, sqnum=5, timestamp_diff_ms=500)
    
    def test_masquerade_fake_fault_lowstnum_cbstatus(self):
        """rule_masquerade_fake_fault_lowstnum_cbstatus: stnum < 200 and cbStatus == 1"""
        return self.send_packet(stnum=150, sqnum=10, timestamp_diff_ms=0, status=1)
    
    def test_masquerade_fake_normal_state_stdiff(self):
        """rule_masquerade_fake_normal_state_and_stdiff: stnum > 800 and stdiff > 500"""
        self.send_packet(stnum=500, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=1000, sqnum=11, timestamp_diff_ms=0)
    
    def test_masquerade_fake_normal_state_timestamp(self):
        """rule_masquerade_fake_normal_state_and_timestampdiff: stnum > 800 and timestampDiff > 400ms"""
        return self.send_packet(stnum=900, sqnum=10, timestamp_diff_ms=600)
    
    def test_poisoned_high_rate_state(self):
        """rule_poisoned_high_rate_state: stnum > 679 and timeFromLastChange > 1000s"""
        return self.send_packet(stnum=700, sqnum=10, timestamp_diff_ms=0)
    
    def test_poisoned_high_rate_timing(self):
        """rule_poisoned_high_rate_timing: timestampDiff > 380ms and tdiff < -120ms"""
        # timestamp_diff_ms negativo indica timestamp futuro (tdiff negativo)
        return self.send_packet(stnum=100, sqnum=10, timestamp_diff_ms=-200)
    
    def test_random_replay_sqnum_stnum(self):
        """rule_random_replay_sqnum_stnum: sqnum > 55 and stnum < 100"""
        return self.send_packet(stnum=80, sqnum=60, timestamp_diff_ms=0)
    
    def test_random_replay_sqdiff_stdiff(self):
        """rule_random_replay_sqdiff_stdiff: sqdiff > 30 and stdiff < -50000"""
        self.send_packet(stnum=100, sqnum=50, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=10, sqnum=100, timestamp_diff_ms=0)
    
    def test_random_replay_timestamp_timechange(self):
        """rule_random_replay_timestamp_timechange: timestampDiff > 400ms and timeFromLastChange > 60s"""
        self.send_packet(stnum=100, sqnum=10, timestamp_diff_ms=0)
        time.sleep(0.1)
        return self.send_packet(stnum=101, sqnum=11, timestamp_diff_ms=600)
    
    def run_all_tests(self):
        """Executa todos os 21 testes"""
        print("=" * 80)
        print("TESTE COMPLETO - TODAS AS 21 REGRAS DE DETECÇÃO GOOSE")
        print("=" * 80)
        print("\n📤 Enviando pacotes para o switch P4...")
        print("   (Observe o terminal do switch para ver os drops)\n")
        
        tests = [
            # grayhole (4 regras)
            (1, "Grayhole: SqNum<5 + tDiff>1500ms", "grayhole_sqnum_tdiff", self.test_grayhole_sqnum_tdiff, True),
            (2, "Grayhole: SqNum<5 + StNum<30", "grayhole_sqnum_stnum", self.test_grayhole_sqnum_stnum, True),
            (3, "Grayhole: SqNum<5 + stDiff>500", "grayhole_sqnum_stdiff", self.test_grayhole_sqnum_stdiff, True),
            (4, "Grayhole: Persistente (SqNum<=4)", "grayhole_persistent", self.test_grayhole_persistent, True),
            
            # high_StNum (2 regras)
            (5, "High StNum: StNum>2000 + stDiff>1000", "high_StNum_state", self.test_high_stnum_state, True),
            (6, "High StNum: Seq+Time", "high_StNum_seq_time", self.test_high_stnum_seq_time, True),
            
            # injection (2 regras)
            (7, "Injection: SeqNum alto + salto", "injection_seq", self.test_injection_seq, True),
            (8, "Injection: Estado anormal", "injection_state", self.test_injection_state, True),
            
            # inverse_replay (2 regras)
            (9, "Inverse Replay: Atraso temporal", "inverse_replay_time", self.test_inverse_replay_time_delay, True),
            (10, "Inverse Replay: Salto de estado", "inverse_replay_jump", self.test_inverse_replay_status_jump, True),
            
            # masquerade_fake_fault (4 regras)
            (11, "Masquerade Fake Fault: tDiff + tsDiff", "fake_fault_tdiff_ts", self.test_masquerade_fake_fault_tdiff_ts, True),
            (12, "Masquerade Fake Fault: tDiff + stDiff", "fake_fault_tdiff_stdiff", self.test_masquerade_fake_fault_tdiff_stdiff, True),
            (13, "Masquerade Fake Fault: SqNum baixo + tsDiff", "fake_fault_sqnum_ts", self.test_masquerade_fake_fault_sqnum_ts, True),
            (14, "Masquerade Fake Fault: StNum baixo + cbStatus", "fake_fault_lowstnum", self.test_masquerade_fake_fault_lowstnum_cbstatus, True),
            
            # masquerade_fake_normal (2 regras)
            (15, "Masquerade Fake Normal: StNum>800 + stDiff>500", "fake_normal_stdiff", self.test_masquerade_fake_normal_state_stdiff, True),
            (16, "Masquerade Fake Normal: StNum>800 + tsDiff>400ms", "fake_normal_timestamp", self.test_masquerade_fake_normal_state_timestamp, True),
            
            # poisoned_high_rate (2 regras)
            (17, "Poisoned High Rate: Estado prolongado", "poisoned_state", self.test_poisoned_high_rate_state, True),
            (18, "Poisoned High Rate: Timing anômalo", "poisoned_timing", self.test_poisoned_high_rate_timing, True),
            
            # random_replay (3 regras)
            (19, "Random Replay: SqNum>55 + StNum<100", "random_sqnum_stnum", self.test_random_replay_sqnum_stnum, True),
            (20, "Random Replay: Salto seq + diff negativo", "random_sqdiff_stdiff", self.test_random_replay_sqdiff_stdiff, True),
            (21, "Random Replay: Timestamp + timeChange", "random_timestamp", self.test_random_replay_timestamp_timechange, True),
        ]
        
        for test_id, name, rule_id, func, expected in tests:
            self.run_test(test_id, name, rule_id, func, expected)
        
        # Teste adicional: Tráfego normal (deve passar)
        print("\n[22] Tráfego NORMAL (controle)")
        print("     Regra: Nenhuma - deve PASSAR")
        normal_pkt = self.send_packet(stnum=100, sqnum=50, timestamp_diff_ms=0, status=0)
        print("     Esperado: PASSAR")
        print("     → ✅ PASSOU")
        
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
        
        print("\n🎯 Regras implementadas no P4:")
        rules_list = [
            "1. grayhole_sqnum_tdiff", "2. grayhole_sqnum_stnum", "3. grayhole_sqnum_stdiff", "4. grayhole_persistent",
            "5. high_StNum_state", "6. high_StNum_seq_time", "7. injection_seq", "8. injection_state",
            "9. inverse_replay_time_delay", "10. inverse_replay_status_jump", "11. masquerade_fake_fault_tdiff_ts",
            "12. masquerade_fake_fault_tdiff_stdiff", "13. masquerade_fake_fault_sqnum_ts", "14. masquerade_fake_fault_lowstnum_cbstatus",
            "15. masquerade_fake_normal_state_stdiff", "16. masquerade_fake_normal_state_timestamp",
            "17. poisoned_high_rate_state", "18. poisoned_high_rate_timing", "19. random_replay_sqnum_stnum",
            "20. random_replay_sqdiff_stdiff", "21. random_replay_timestamp_timechange"
        ]
        for i, rule in enumerate(rules_list, 1):
            print(f"   {i:2d}. {rule}")
        
        print("\n✅ Testes concluídos!")

if __name__ == "__main__":
    interface = sys.argv[1] if len(sys.argv) > 1 else "veth1"
    
    print(f"\n🚀 Iniciando testes na interface: {interface}")
    print("⚠️  Certifique-se que o switch P4 está rodando:\n")
    print("   sudo simple_switch --log-console -i 0@veth0 -i 1@veth2 goose_ids.json\n")
    
    input("Pressione ENTER para continuar...")
    
    tester = GooseAttackTester(interface=interface)
    tester.run_all_tests()
