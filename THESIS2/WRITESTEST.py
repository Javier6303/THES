from smartcard.System import readers
from smartcard.util import toBytes

def write_to_nfc_card(text_payload):
    try:
        # Get the list of available readers
        r = readers()
        if not r:
            print("No NFC readers found.")
            return

        # Select the first reader
        reader = r[0]
        connection = reader.createConnection()
        connection.connect()

        print(f"NFC card detected using: {reader}")

        # Command to get the card UID
        GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
        uid_response, sw1, sw2 = connection.transmit(GET_UID)

        if sw1 == 0x90 and sw2 == 0x00:
            uid = ''.join(f'{x:02X}' for x in uid_response)
            print(f"Card UID: {uid}")
        else:
            print(f"Failed to retrieve UID. SW1: {sw1}, SW2: {sw2}")
            return

        # Step 1: Create NDEF message for the payload
        language_code = "en"  # 2-byte language code
        language_code_length = len(language_code)
        text_bytes = text_payload.encode("utf-8")
        text_length = len(text_bytes)

        # Create the NDEF record
        ndef_message = [
            0x03,  # NDEF TLV type
            text_length + 7,  # Length of the NDEF message (payload + metadata)
            0xD1,  # NDEF record header (short record, NFC Well Known Type)
            0x01,  # Type length (1 byte, for "T" type)
            text_length + 3,  # Payload length (text + language code + status byte)
            0x54,  # Type field ("T" for Text)
            language_code_length,  # Status byte (length of the language code)
        ] + list(language_code.encode("utf-8")) + list(text_bytes) + [0xFE]  # Terminator TLV

        # Pad NDEF message to align with 4-byte pages
        while len(ndef_message) % 4 != 0:
            ndef_message.append(0x00)

        # Step 2: Write the NDEF message to the card
        page = 4  # Start writing at Address 04
        for i in range(0, len(ndef_message), 4):
            chunk = ndef_message[i:i+4]
            WRITE_COMMAND = [0xFF, 0xD6, 0x00, page, 0x04] + chunk
            response, sw1, sw2 = connection.transmit(WRITE_COMMAND)
            if sw1 == 0x90 and sw2 == 0x00:
                print(f"Successfully wrote to page {page}: {chunk}")
                page += 1
            else:
                print(f"Failed to write to page {page}. SW1: {sw1}, SW2: {sw2}")
                break

        print("Write operation complete.")

    except Exception as e:
        print(f"Error: {e}")


# Call the function with the text payload
write_to_nfc_card("Hello, NFC!")
