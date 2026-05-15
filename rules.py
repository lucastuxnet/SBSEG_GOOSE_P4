# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 14/05/2026 09:49:57
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_grayhole_sqnum_tdiff(packet: dict) -> bool:
    """Detect low SqNum combined with high tDiff."""
    sq_num = packet.get("SqNum", 0)
    t_diff = packet.get("tDiff", 0)
    return (sq_num < 5) and (t_diff > 1500)

def rule_grayhole_sqnum_stnum(packet: dict) -> bool:
    """Detect low SqNum together with abnormally low StNum."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num < 5) and (st_num < 30)

def rule_grayhole_sqnum_stdiff(packet: dict) -> bool:
    """Detect low SqNum combined with unusually high stDiff."""
    sq_num = packet.get("SqNum", 0)
    st_diff = packet.get("stDiff", 0)
    return (sq_num < 5) and (st_diff > 500)

def rule_grayhole_persistent(packet: dict) -> bool:
    """Detect sustained low SqNum with long time since last change."""
    sq_num = packet.get("SqNum", 0)
    timestamp_diff = packet.get("timestampDiff", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    return (sq_num <= 4) and (timestamp_diff <= 0.2) and (time_from_last_change > 100)


# === high_StNum ===

def rule_high_StNum_state(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum baseado em StNum e stDiff."""
    stnum = packet.get("StNum", 0)
    stdiff = packet.get("stDiff", 0)
    return (stnum > 2000) and (stdiff > 1000)

def rule_high_StNum_seq_time(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum baseado em SqNum, sqDiff, tDiff e timestampDiff."""
    sqnum = packet.get("SqNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    tdiff = packet.get("tDiff", 0)
    timestampdiff = packet.get("timestampDiff", 0)
    return (sqnum > 100) and (sqdiff > 50) and (tdiff > 3000) and (timestampdiff > 0.5)


# === injection ===

def rule_injection_seq(packet: dict) -> bool:
    """Detect injection based on abnormal sequence numbers."""
    sq_num = packet.get("SqNum", 0)
    sq_diff = packet.get("sqDiff", 0)
    return (sq_num > 80) and (sq_diff > 100)

def rule_injection_state(packet: dict) -> bool:
    """Detect injection based on abnormal state numbers and status."""
    st_num = packet.get("StNum", 0)
    st_diff = packet.get("stDiff", 0)
    cb_status = packet.get("cbStatus", 0)
    return (st_num < 20) and (st_diff < -65000) and (cb_status > 1.5)


# === inverse_replay ===

def rule_inverse_replay_time_delay(packet: dict) -> bool:
    """Retorna True se o pacote apresentar indícios de inverse replay via tempo."""
    t_diff = packet.get("tDiff", 0)
    time_since_change = packet.get("timeFromLastChange", 0)
    return (t_diff > 2500) and (time_since_change > 180)

def rule_inverse_replay_status_jump(packet: dict) -> bool:
    """Retorna True se o pacote apresentar indícios de inverse replay via contadores."""
    st_num = packet.get("StNum", 0)
    st_diff = packet.get("stDiff", 0)
    return (st_num < 30) and (st_diff > 400)


# === masquerade_fake_fault ===

def rule_masquerade_fake_fault_tdiff_ts(packet: dict) -> bool:
    """Detect masquerade_fake_fault using high tDiff and timestampDiff."""
    t_diff = packet.get("tDiff", 0)
    ts_diff = packet.get("timestampDiff", 0)
    return (t_diff > 1000) and (ts_diff > 0.2)

def rule_masquerade_fake_fault_tdiff_stdiff(packet: dict) -> bool:
    """Detect masquerade_fake_fault using high tDiff combined with large stDiff."""
    t_diff = packet.get("tDiff", 0)
    st_diff = packet.get("stDiff", 0)
    return (t_diff > 1000) and (st_diff > 300)

def rule_masquerade_fake_fault_sqnum_ts(packet: dict) -> bool:
    """Detect masquerade_fake_fault using low sqNum together with elevated timestampDiff."""
    sq_num = packet.get("SqNum", 0)
    ts_diff = packet.get("timestampDiff", 0)
    return (sq_num < 10) and (ts_diff > 0.3)

def rule_masquerade_fake_fault_lowstnum_cbstatus(packet: dict) -> bool:
    """Detect masquerade_fake_fault using unusually low StNum and constant closed breaker status."""
    st_num = packet.get("StNum", 0)
    cb_status = packet.get("cbStatus", 0)
    return (st_num < 200) and (cb_status == 1)


# === masquerade_fake_normal ===

def rule_masquerade_fake_normal_state_and_stdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    st_num = packet.get("StNum", 0)
    st_diff = packet.get("stDiff", 0)
    return (st_num > 800) and (st_diff > 500)

def rule_masquerade_fake_normal_state_and_timestampdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    st_num = packet.get("StNum", 0)
    timestamp_diff = packet.get("timestampDiff", 0)
    return (st_num > 800) and (timestamp_diff > 0.4)


# === poisoned_high_rate ===

def rule_poisoned_high_rate_state(packet: dict) -> bool:
    """Retorna True se o pacote apresentar indícios de poisoned_high_rate via estado prolongado."""
    stnum = packet.get("StNum", 0)
    time_last = packet.get("timeFromLastChange", 0)
    return (stnum > 679) and (time_last > 1000)

def rule_poisoned_high_rate_timing(packet: dict) -> bool:
    """Retorna True se o pacote apresentar indícios de poisoned_high_rate via anomalias temporais."""
    ts_diff = packet.get("timestampDiff", 0)
    delay = packet.get("delay", 0)
    tdiff = packet.get("tDiff", 0)
    return (ts_diff > 0.38) and (delay > 0.0005) and (tdiff < -120.5)


# === random_replay ===

def rule_random_replay_sqnum_stnum(packet: dict) -> bool:
    """High sequence number together with unusually low state number."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num > 55) and (st_num < 100)

def rule_random_replay_sqdiff_stdiff(packet: dict) -> bool:
    """Large jump in sequence diff combined with extreme negative state diff."""
    sq_diff = packet.get("sqDiff", 0)
    st_diff = packet.get("stDiff", 0)
    return (sq_diff > 30) and (st_diff < -50000)

def rule_random_replay_timestamp_timechange(packet: dict) -> bool:
    """Timestamp far from arrival time and long interval since last change."""
    ts_diff = packet.get("timestampDiff", 0)
    time_last_change = packet.get("timeFromLastChange", 0)
    return (ts_diff > 0.4) and (time_last_change > 60)

