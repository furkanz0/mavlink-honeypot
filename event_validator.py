# event_validator.py
# events.json sozlesmesini dogrulayan validator modulu
# Asama 6: Event Validation Sistemi

ALLOWED_FIELDS = {
    "timestamp",
    "source_ip",
    "source_port",
    "protocol",
    "message_type",
    "status"
}

ALLOWED_PROTOCOLS = {"UDP", "TCP"}
ALLOWED_STATUSES = {"NORMAL", "SUSPIC"}


def validate_event_with_reason(event):
    """
    Event sozlesmesini kontrol eder ve varsa hata nedenini dondurur.

    Returns:
        tuple: (is_valid: bool, reason: str or None)
    """
    # 1. Event dictionary mi?
    if not isinstance(event, dict):
        return False, "Event bir sozluk (dict) olmalidir."

    # 2. Tam olarak 6 alan var mi?
    if len(event) != 6:
        return False, f"Event tam olarak 6 alan icermelidir. Mevcut alan sayisi: {len(event)}"

    # 3. Alan isimleri dogru mu?
    event_keys = set(event.keys())
    if event_keys != ALLOWED_FIELDS:
        missing = ALLOWED_FIELDS - event_keys
        extra = event_keys - ALLOWED_FIELDS
        reasons = []
        if missing:
            reasons.append(f"Eksik alanlar: {missing}")
        if extra:
            reasons.append(f"Fazla/Gecersiz alanlar: {extra}")
        return False, "; ".join(reasons)

    # 4. timestamp string mi?
    if not isinstance(event["timestamp"], str):
        return False, f"timestamp bir string olmalidir. Mevcut tip: {type(event['timestamp']).__name__}"

    # 5. source_ip string mi?
    if not isinstance(event["source_ip"], str):
        return False, f"source_ip bir string olmalidir. Mevcut tip: {type(event['source_ip']).__name__}"

    # 6. source_port integer mi? (Python'da bool integer alt sinifidir, bu yuzden bool kontrolu de yapilir)
    if isinstance(event["source_port"], bool) or not isinstance(event["source_port"], int):
        return False, f"source_port bir integer olmalidir. Mevcut tip: {type(event['source_port']).__name__}"

    # 7. protocol UDP veya TCP mi?
    if event["protocol"] not in ALLOWED_PROTOCOLS:
        return False, f"protocol sadece 'UDP' veya 'TCP' olabilir. Mevcut deger: '{event['protocol']}'"

    # 8. message_type string mi?
    if not isinstance(event["message_type"], str):
        return False, f"message_type bir string olmalidir. Mevcut tip: {type(event['message_type']).__name__}"

    # 9. status NORMAL veya SUSPIC mi?
    if event["status"] not in ALLOWED_STATUSES:
        return False, f"status sadece 'NORMAL' veya 'SUSPIC' olabilir ('SUSPICIOUS' kullanilamaz). Mevcut deger: '{event['status']}'"

    return True, None


def validate_event(event):
    """
    Event'in events.json sozlesmesine uygun olup olmadigini kontrol eder.

    Args:
        event (dict): Dogrulanacak event verisi.

    Returns:
        bool: Gecerli ise True, gecersiz ise False.
    """
    is_valid, _ = validate_event_with_reason(event)
    return is_valid
