# mavlink_responder.py
# Sahte MAVLink cevaplari ureten modul
# Honeypot'un gercek bir IHA gibi gorunmesini saglar
#
# NOT: Bu gercek bir IHA kontrolcusu degildir.
# Gercek HA baglantisi kurulmaz, gercek ucus kontrolu yapilmaz.
# Amac: Saldirganin gercek bir sistemle iletisim kurdugunun
# dusunmesini saglayarak davranisini gozlemlemektir.

from pymavlink import mavutil

# Sahte IHA bilgileri (honeypot kimligi)
FAKE_SYSTEM_ID = 1
FAKE_COMPONENT_ID = 1


def create_responder():
    """Sahte cevap gondermek icin MAVLink nesnesi olusturur"""
    mav = mavutil.mavlink.MAVLink(
        None,
        srcSystem=FAKE_SYSTEM_ID,
        srcComponent=FAKE_COMPONENT_ID
    )
    return mav


def generate_response(mav, message_type):
    """
    Gelen mesaj tipine gore sahte MAVLink cevabi uretir.

    Desteklenen cevaplar:
        HEARTBEAT           -> Sahte HEARTBEAT (drone aktif gorunur)
        PARAM_REQUEST_LIST  -> Sahte PARAM_VALUE (parametre listesi)
        PARAM_SET           -> Sahte PARAM_VALUE (parametre degisti onay)
        COMMAND_LONG        -> Sahte COMMAND_ACK (komut kabul edildi)

    Cevap uretilemeyen mesajlar icin None doner.

    Returns:
        (response_bytes, description) veya (None, None)
        response_bytes: Gonderilecek sahte cevap byte verisi
        description: Terminal icin aciklama metni
    """

    try:

        if message_type == "HEARTBEAT":
            # Sahte HEARTBEAT: "Ben aktif bir quadrotor'um" mesaji
            response = mav.heartbeat_encode(
                type=mavutil.mavlink.MAV_TYPE_QUADROTOR,
                autopilot=mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                base_mode=mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED,
                custom_mode=0,
                system_status=mavutil.mavlink.MAV_STATE_ACTIVE
            )
            return (response.pack(mav), "Sahte HEARTBEAT cevabi gonderildi.")

        elif message_type == "PARAM_REQUEST_LIST":
            # Sahte PARAM_VALUE: test parametresi doner
            # Gercek parametre degil, sadece honeypot simülasyonu
            response = mav.param_value_encode(
                param_id=b"TEST_PARAM_1\x00\x00\x00\x00",  # 16 byte
                param_value=100.0,
                param_type=mavutil.mavlink.MAV_PARAM_TYPE_REAL32,
                param_count=3,       # Sahte: "3 parametrem var"
                param_index=0
            )
            return (response.pack(mav), "Sahte PARAM_VALUE cevabi gonderildi. (TEST_PARAM_1)")

        elif message_type == "PARAM_SET":
            # Sahte PARAM_VALUE: "Parametre degistirildi" onay cevabi
            # Gercek parametre degistirilmez, sadece onay simule edilir
            response = mav.param_value_encode(
                param_id=b"TEST_MODE\x00\x00\x00\x00\x00\x00\x00",  # 16 byte
                param_value=1.0,
                param_type=mavutil.mavlink.MAV_PARAM_TYPE_REAL32,
                param_count=3,
                param_index=2
            )
            return (response.pack(mav), "Sahte PARAM_VALUE onay cevabi gonderildi. Gercek parametre degistirilmedi.")

        elif message_type == "COMMAND_LONG":
            # Sahte COMMAND_ACK: "Komut kabul edildi" cevabi
            # Gercek komut yurutulmez, sadece onay simule edilir
            response = mav.command_ack_encode(
                command=0,
                result=mavutil.mavlink.MAV_RESULT_ACCEPTED
            )
            return (response.pack(mav), "Sahte COMMAND_ACK cevabi gonderildi. Komut gercek sistemde calistirilmadi.")

    except Exception as e:
        # Sahte cevap uretilemezse hata mesaji dondur
        return (None, f"Sahte cevap uretilirken hata: {e}")

    # Bu mesaj tipi icin cevap tanimlanmamis
    return (None, None)
