/* GOOSE IEC 61850 Anomaly Detection - Complete Rules */
/* Versão corrigida - sem erros de conversão */

#include <core.p4>
#include <v1model.p4>

/* Headers */
header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ethertype;
}

header goose_t {
    bit<16> appid;
    bit<16> reserved;
    bit<32> stnum;      /* State number */
    bit<32> sqnum;      /* Sequence number */
    bit<64> timestamp;  /* Timestamp in milliseconds */
    bit<8>  status;     /* Breaker status */
    bit<24> padding;    /* Alinhamento */
}

/* Metadata para estado e cálculos */
struct metadata {
    /* Diferenças calculadas (usando bit<32> para valores absolutos) */
    bit<32> sqdiff;         /* Delta entre SqNum atual e anterior */
    bit<32> stdiff;         /* Delta entre StNum atual e anterior */
    bit<32> tdiff;          /* Diferença de timestamp (ms) */
    bit<32> timestamp_diff; /* Diferença entre chegada e timestamp (ms) */
    
    /* Estado anterior */
    bit<32> last_stnum;
    bit<32> last_sqnum;
    bit<64> last_timestamp;
    bit<48> last_arrival_time;
    bit<48> last_change_time;
    
    /* Flags */
    bit<1>  state_valid;
    bit<1>  is_first_packet;
    
    /* Para detecção de diferenças negativas */
    bit<1>  stdiff_negative;
    bit<1>  tdiff_negative;
}

struct headers {
    ethernet_t ethernet;
    goose_t    goose;
}

/* Parser */
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethertype) {
            0x88B8: parse_goose;
            default: accept;
        }
    }
    state parse_goose {
        packet.extract(hdr.goose);
        transition accept;
    }
}

/* Verify Checksum (vazio) */
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/* Ingress Pipeline com todas as regras */
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    /* Ação para atualizar estado e calcular diferenças */
    action update_state() {
        // Obtém tempo atual de chegada
        meta.last_arrival_time = standard_metadata.ingress_global_timestamp;
        
        if (meta.state_valid == 1) {
            // Calcula diferenças (valores absolutos)
            if (hdr.goose.sqnum >= meta.last_sqnum) {
                meta.sqdiff = hdr.goose.sqnum - meta.last_sqnum;
            } else {
                meta.sqdiff = meta.last_sqnum - hdr.goose.sqnum;
            }
            
            if (hdr.goose.stnum >= meta.last_stnum) {
                meta.stdiff = hdr.goose.stnum - meta.last_stnum;
                meta.stdiff_negative = 0;
            } else {
                meta.stdiff = meta.last_stnum - hdr.goose.stnum;
                meta.stdiff_negative = 1;
            }
            
            // Diferença de timestamp
            if (hdr.goose.timestamp >= meta.last_timestamp) {
                meta.tdiff = (bit<32>)(hdr.goose.timestamp - meta.last_timestamp);
                meta.tdiff_negative = 0;
            } else {
                meta.tdiff = (bit<32>)(meta.last_timestamp - hdr.goose.timestamp);
                meta.tdiff_negative = 1;
            }
            
            // Diferença entre tempo de chegada e timestamp
            if ((bit<64>)meta.last_arrival_time >= hdr.goose.timestamp) {
                meta.timestamp_diff = (bit<32>)((bit<64>)meta.last_arrival_time - hdr.goose.timestamp);
            } else {
                meta.timestamp_diff = (bit<32>)(hdr.goose.timestamp - (bit<64>)meta.last_arrival_time);
            }
            
            // Verifica se StNum mudou para timeFromLastChange
            if (hdr.goose.stnum != meta.last_stnum) {
                meta.last_change_time = standard_metadata.ingress_global_timestamp;
            }
        } else {
            // Primeiro pacote - inicializa
            meta.state_valid = 1;
            meta.is_first_packet = 1;
            meta.sqdiff = 0;
            meta.stdiff = 0;
            meta.tdiff = 0;
            meta.timestamp_diff = 0;
            meta.stdiff_negative = 0;
            meta.tdiff_negative = 0;
            meta.last_change_time = standard_metadata.ingress_global_timestamp;
        }
        
        // Salva estado atual
        meta.last_stnum = hdr.goose.stnum;
        meta.last_sqnum = hdr.goose.sqnum;
        meta.last_timestamp = hdr.goose.timestamp;
    }
    
    /* Ação para dropar pacote */
    action drop_packet() {
        mark_to_drop(standard_metadata);
    }
    
    apply {
        if (hdr.goose.isValid()) {
            update_state();
            
            // ============================================
            // === grayhole (SQNUM < 5) ===
            // ============================================
            
            // rule_grayhole_sqnum_tdiff: low SqNum with high tDiff (tDiff > 1500ms)
            if (hdr.goose.sqnum < 5 && meta.tdiff > 1500) {
                drop_packet();
            }
            // rule_grayhole_sqnum_stnum: low SqNum with low StNum (StNum < 30)
            else if (hdr.goose.sqnum < 5 && hdr.goose.stnum < 30) {
                drop_packet();
            }
            // rule_grayhole_sqnum_stdiff: low SqNum with high stDiff (stDiff > 500)
            else if (hdr.goose.sqnum < 5 && meta.stdiff > 500) {
                drop_packet();
            }
            // rule_grayhole_persistent: sustained low SqNum 
            else if (meta.state_valid == 1 && meta.is_first_packet == 0 && 
                     hdr.goose.sqnum <= 4 && 
                     meta.timestamp_diff <= 200 && 
                     ((bit<64>)meta.last_arrival_time - (bit<64>)meta.last_change_time) > 100000000) {
                drop_packet();
            }
            
            // ============================================
            // === high_StNum ===
            // ============================================
            
            // rule_high_StNum_state: StNum > 2000 and stDiff > 1000
            else if (hdr.goose.stnum > 2000 && meta.stdiff > 1000) {
                drop_packet();
            }
            // rule_high_StNum_seq_time: sqnum > 100 and sqdiff > 50 and tdiff > 3000 and timestampDiff > 500ms
            else if (hdr.goose.sqnum > 100 && meta.sqdiff > 50 && 
                     meta.tdiff > 3000 && meta.timestamp_diff > 500) {
                drop_packet();
            }
            
            // ============================================
            // === injection ===
            // ============================================
            
            // rule_injection_seq: sqnum > 80 and sqdiff > 100
            else if (hdr.goose.sqnum > 80 && meta.sqdiff > 100) {
                drop_packet();
            }
            // rule_injection_state: stnum < 20 and stdiff > 65000 (valores negativos são grandes)
            else if (hdr.goose.stnum < 20 && meta.stdiff_negative == 1 && meta.stdiff > 65000) {
                drop_packet();
            }
            
            // ============================================
            // === inverse_replay ===
            // ============================================
            
            // rule_inverse_replay_time_delay: tdiff > 2500ms and timeFromLastChange > 180s
            else if (meta.state_valid == 1 && meta.is_first_packet == 0 && 
                     meta.tdiff > 2500 && 
                     ((bit<64>)meta.last_arrival_time - (bit<64>)meta.last_change_time) > 180000000) {
                drop_packet();
            }
            // rule_inverse_replay_status_jump: stnum < 30 and stdiff > 400
            else if (hdr.goose.stnum < 30 && meta.stdiff > 400) {
                drop_packet();
            }
            
            // ============================================
            // === masquerade_fake_fault ===
            // ============================================
            
            // rule_masquerade_fake_fault_tdiff_ts: tdiff > 1000ms and timestampDiff > 200ms
            else if (meta.tdiff > 1000 && meta.timestamp_diff > 200) {
                drop_packet();
            }
            // rule_masquerade_fake_fault_tdiff_stdiff: tdiff > 1000ms and stdiff > 300
            else if (meta.tdiff > 1000 && meta.stdiff > 300) {
                drop_packet();
            }
            // rule_masquerade_fake_fault_sqnum_ts: sqnum < 10 and timestampDiff > 300ms
            else if (hdr.goose.sqnum < 10 && meta.timestamp_diff > 300) {
                drop_packet();
            }
            // rule_masquerade_fake_fault_lowstnum_cbstatus: stnum < 200 and cbStatus == 1
            else if (hdr.goose.stnum < 200 && hdr.goose.status == 1) {
                drop_packet();
            }
            
            // ============================================
            // === masquerade_fake_normal ===
            // ============================================
            
            // rule_masquerade_fake_normal_state_and_stdiff: stnum > 800 and stdiff > 500
            else if (hdr.goose.stnum > 800 && meta.stdiff > 500) {
                drop_packet();
            }
            // rule_masquerade_fake_normal_state_and_timestampdiff: stnum > 800 and timestampDiff > 400ms
            else if (hdr.goose.stnum > 800 && meta.timestamp_diff > 400) {
                drop_packet();
            }
            
            // ============================================
            // === poisoned_high_rate ===
            // ============================================
            
            // rule_poisoned_high_rate_state: stnum > 679 and timeFromLastChange > 1000s
            else if (meta.state_valid == 1 && meta.is_first_packet == 0 && 
                     hdr.goose.stnum > 679 && 
                     ((bit<64>)meta.last_arrival_time - (bit<64>)meta.last_change_time) > 1000000000) {
                drop_packet();
            }
            // rule_poisoned_high_rate_timing: timestampDiff > 380ms and tdiff negativo (< -120)
            else if (meta.timestamp_diff > 380 && meta.tdiff_negative == 1 && meta.tdiff > 120) {
                drop_packet();
            }
            
            // ============================================
            // === random_replay ===
            // ============================================
            
            // rule_random_replay_sqnum_stnum: sqnum > 55 and stnum < 100
            else if (hdr.goose.sqnum > 55 && hdr.goose.stnum < 100) {
                drop_packet();
            }
            // rule_random_replay_sqdiff_stdiff: sqdiff > 30 and stdiff_negative and stdiff > 50000
            else if (meta.sqdiff > 30 && meta.stdiff_negative == 1 && meta.stdiff > 50000) {
                drop_packet();
            }
            // rule_random_replay_timestamp_timechange: timestampDiff > 400ms and timeFromLastChange > 60s
            else if (meta.state_valid == 1 && meta.is_first_packet == 0 && 
                     meta.timestamp_diff > 400 && 
                     ((bit<64>)meta.last_arrival_time - (bit<64>)meta.last_change_time) > 60000000) {
                drop_packet();
            }
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.goose);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
