/* GOOSE IEC 61850 Anomaly Detection - Complete Rules */
/* Versão corrigida - sem erros de conversão */
/* Gerado automaticamente em: 2026-05-15 17:11:10 */
/* Total de regras: 21 */

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

    /* Delay para poisoned_high_rate */
    bit<32> delay;
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
            meta.delay = 0;
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
            
            // rule_grayhole_sqnum_tdiff
            if (hdr.goose.hdr.goose.hdr.goose.sqnum = packet.get("hdr.goose.hdr.goose.sqnum", 0) meta.meta.meta.tdiff = packet.get("meta.meta.tdiff", 0) (hdr.goose.hdr.goose.hdr.goose.sqnum < 5) && (meta.meta.meta.tdiff > 1500)) {
                drop_packet();
            }
            
            // rule_grayhole_sqnum_stnum
            else if (hdr.goose.hdr.goose.hdr.goose.sqnum = packet.get("hdr.goose.hdr.goose.sqnum", 0) hdr.goose.hdr.goose.hdr.goose.stnum = packet.get("hdr.goose.hdr.goose.stnum", 0) (hdr.goose.hdr.goose.hdr.goose.sqnum < 5) && (hdr.goose.hdr.goose.hdr.goose.stnum < 30)) {
                drop_packet();
            }
            
            // rule_grayhole_sqnum_stdiff
            else if (hdr.goose.hdr.goose.hdr.goose.sqnum = packet.get("hdr.goose.hdr.goose.sqnum", 0) meta.meta.meta.stdiff = packet.get("meta.meta.stdiff", 0) (hdr.goose.hdr.goose.hdr.goose.sqnum < 5) && (meta.meta.meta.stdiff > 500)) {
                drop_packet();
            }
            
            // rule_grayhole_persistent
            else if (hdr.goose.hdr.goose.hdr.goose.sqnum = packet.get("hdr.goose.hdr.goose.sqnum", 0) meta.timestamp_diff = packet.get("meta.timestamp_diff", 0) meta.time_from_last_change_calc = packet.get("meta.time_from_last_change_calc", 0) (hdr.goose.hdr.goose.hdr.goose.sqnum <= 4) && (meta.timestamp_diff <= 200) && (((bit<64>)meta.last_arrival_time - (bit<64>)meta.last_change_time) > 100000000000)) {
                drop_packet();
            }
            
            // ============================================
            // === high_StNum ===
            // ============================================
            
            // rule_high_StNum_state
            if (hdr.goose.hdr.goose.stnum = packet.get("hdr.goose.hdr.goose.stnum", 0) meta.meta.stdiff = packet.get("meta.meta.stdiff", 0) (hdr.goose.hdr.goose.stnum > 2000) && (meta.meta.stdiff > 1000)) {
                drop_packet();
            }
            
            // rule_high_StNum_seq_time
            else if (hdr.goose.hdr.goose.sqnum = packet.get("hdr.goose.hdr.goose.sqnum", 0) meta.meta.sqdiff = packet.get("meta.meta.sqdiff", 0) meta.meta.tdiff = packet.get("meta.meta.tdiff", 0) meta.timestamp_diff = packet.get("meta.timestamp_diff", 0) (hdr.goose.hdr.goose.sqnum > 100) && (meta.meta.sqdiff > 50) && (meta.meta.tdiff > 3000) && (meta.timestamp_diff > 500)) {
                drop_packet();
            }
            
            // ============================================
            // === injection ===
            // ============================================
            
            // rule_injection_seq
            if (hdr.goose.hdr.goose.hdr.goose.sqnum = packet.get("hdr.goose.hdr.goose.sqnum", 0) meta.meta.meta.sqdiff = packet.get("meta.meta.sqdiff", 0) (hdr.goose.hdr.goose.hdr.goose.sqnum > 80) && (meta.meta.meta.sqdiff > 100)) {
                drop_packet();
            }
            
            // rule_injection_state
            else if (hdr.goose.hdr.goose.hdr.goose.stnum = packet.get("hdr.goose.hdr.goose.stnum", 0) meta.meta.meta.stdiff = packet.get("meta.meta.stdiff", 0) hdr.goose.status = packet.get("hdr.goose.status", 0) (hdr.goose.hdr.goose.hdr.goose.stnum < 20) && (meta.meta.meta.stdiff < -65000) && (hdr.goose.status > 1.5)) {
                drop_packet();
            }
            
            // ============================================
            // === inverse_replay ===
            // ============================================
            
            // rule_inverse_replay_time_delay
            if (meta.meta.meta.tdiff = packet.get("meta.meta.tdiff", 0) meta.time_from_last_change_calc = packet.get("meta.time_from_last_change_calc", 0) (meta.meta.meta.tdiff > 2500) && (((bit<64>)meta.last_arrival_time - (bit<64>)meta.last_change_time) > 180000000000)) {
                drop_packet();
            }
            
            // rule_inverse_replay_status_jump
            else if (hdr.goose.hdr.goose.hdr.goose.stnum = packet.get("hdr.goose.hdr.goose.stnum", 0) meta.meta.meta.stdiff = packet.get("meta.meta.stdiff", 0) (hdr.goose.hdr.goose.hdr.goose.stnum < 30) && (meta.meta.meta.stdiff > 400)) {
                drop_packet();
            }
            
            // ============================================
            // === masquerade_fake_fault ===
            // ============================================
            
            // rule_masquerade_fake_fault_tdiff_ts
            if (meta.meta.meta.tdiff = packet.get("meta.meta.tdiff", 0) meta.timestamp_diff = packet.get("meta.timestamp_diff", 0) (meta.meta.meta.tdiff > 1000) && (meta.timestamp_diff > 200)) {
                drop_packet();
            }
            
            // rule_masquerade_fake_fault_tdiff_stdiff
            else if (meta.meta.meta.tdiff = packet.get("meta.meta.tdiff", 0) meta.meta.meta.stdiff = packet.get("meta.meta.stdiff", 0) (meta.meta.meta.tdiff > 1000) && (meta.meta.meta.stdiff > 300)) {
                drop_packet();
            }
            
            // rule_masquerade_fake_fault_sqnum_ts
            else if (hdr.goose.hdr.goose.hdr.goose.sqnum = packet.get("hdr.goose.hdr.goose.sqnum", 0) meta.timestamp_diff = packet.get("meta.timestamp_diff", 0) (hdr.goose.hdr.goose.hdr.goose.sqnum < 10) && (meta.timestamp_diff > 300)) {
                drop_packet();
            }
            
            // rule_masquerade_fake_fault_lowstnum_cbstatus
            else if (hdr.goose.hdr.goose.hdr.goose.stnum = packet.get("hdr.goose.hdr.goose.stnum", 0) hdr.goose.status = packet.get("hdr.goose.status", 0) (hdr.goose.hdr.goose.hdr.goose.stnum < 200) && (hdr.goose.status == 1)) {
                drop_packet();
            }
            
            // ============================================
            // === masquerade_fake_normal ===
            // ============================================
            
            // rule_masquerade_fake_normal_state_and_stdiff
            if (hdr.goose.hdr.goose.hdr.goose.stnum = packet.get("hdr.goose.hdr.goose.stnum", 0) meta.meta.meta.stdiff = packet.get("meta.meta.stdiff", 0) (hdr.goose.hdr.goose.hdr.goose.stnum > 800) && (meta.meta.meta.stdiff > 500)) {
                drop_packet();
            }
            
            // rule_masquerade_fake_normal_state_and_timestampdiff
            else if (hdr.goose.hdr.goose.hdr.goose.stnum = packet.get("hdr.goose.hdr.goose.stnum", 0) meta.timestamp_diff = packet.get("meta.timestamp_diff", 0) (hdr.goose.hdr.goose.hdr.goose.stnum > 800) && (meta.timestamp_diff > 400)) {
                drop_packet();
            }
            
            // ============================================
            // === poisoned_high_rate ===
            // ============================================
            
            // rule_poisoned_high_rate_state
            if (hdr.goose.hdr.goose.stnum = packet.get("hdr.goose.hdr.goose.stnum", 0) meta.time_from_last_change_calc = packet.get("meta.time_from_last_change_calc", 0) (hdr.goose.hdr.goose.stnum > 679) && (((bit<64>)meta.last_arrival_time - (bit<64>)meta.last_change_time) > 1000000000000)) {
                drop_packet();
            }
            
            // rule_poisoned_high_rate_timing
            else if (meta.timestamp_diff = packet.get("meta.timestamp_diff", 0) meta.delay = packet.get("meta.delay", 0) meta.meta.tdiff = packet.get("meta.meta.tdiff", 0) (meta.timestamp_diff > 380) && (meta.delay > 500000) && (meta.meta.tdiff < -120)) {
                drop_packet();
            }
            
            // ============================================
            // === random_replay ===
            // ============================================
            
            // rule_random_replay_sqnum_stnum
            if (hdr.goose.hdr.goose.hdr.goose.sqnum = packet.get("hdr.goose.hdr.goose.sqnum", 0) hdr.goose.hdr.goose.hdr.goose.stnum = packet.get("hdr.goose.hdr.goose.stnum", 0) (hdr.goose.hdr.goose.hdr.goose.sqnum > 55) && (hdr.goose.hdr.goose.hdr.goose.stnum < 100)) {
                drop_packet();
            }
            
            // rule_random_replay_sqdiff_stdiff
            else if (meta.meta.meta.sqdiff = packet.get("meta.meta.sqdiff", 0) meta.meta.meta.stdiff = packet.get("meta.meta.stdiff", 0) (meta.meta.meta.sqdiff > 30) && (meta.meta.meta.stdiff < -50000)) {
                drop_packet();
            }
            
            // rule_random_replay_timestamp_timechange
            else if (meta.timestamp_diff = packet.get("meta.timestamp_diff", 0) time_last_change = packet.get("meta.time_from_last_change_calc", 0) (meta.timestamp_diff > 400) && (time_last_change > 60)) {
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
