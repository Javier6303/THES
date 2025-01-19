from smartcard.System import readers
from smartcard.util import toHexString

def detect_and_read_ndef_record():
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
            uid = toHexString(uid_response)
            print(f"Card UID: {uid}")
        else:
            print(f"Failed to retrieve UID. SW1: {sw1}, SW2: {sw2}")
            return

        # Start reading NDEF data from Address 04
        ndef_data = []
        for page in range(4, 20):  # Reading from Address 04 to 09
            READ_PAGE = [0xFF, 0xB0, 0x00, page, 0x04]  # Wrapped Read Command
            response, sw1, sw2 = connection.transmit(READ_PAGE)
            if sw1 == 0x90 and sw2 == 0x00:
                print(f"Page {page} Data: {toHexString(response)}")
                ndef_data.extend(response)
            else:
                print(f"Failed to read page {page}. SW1: {sw1}, SW2: {sw2}")
                break

        # Combine and parse the NDEF data
        if ndef_data:
            print("Raw NDEF Data:", toHexString(ndef_data))

            # Parse NDEF Record
            tnf = ndef_data[2] & 0x07  # TNF (Type Name Format)
            type_length = ndef_data[3]  # Length of the Type field
            payload_length = ndef_data[4]  # Length of the Payload field
            type_field = bytes(ndef_data[5:5 + type_length]).decode('utf-8')  # Type field

            # Calculate the start of the actual text payload
            status_byte = ndef_data[5 + type_length]  # Status byte (0x02)
            lang_code_length = status_byte & 0x3F  # Language code length (lower 6 bits of status byte)
            text_start = 5 + type_length + 1 + lang_code_length  # Skip type, status byte, and language code
            text_payload = bytes(ndef_data[text_start:text_start + payload_length - (1 + lang_code_length)])  # Extract actual text

            print(f"TNF: {tnf}")
            print(f"Type: {type_field}")
            print(f"Payload: {text_payload.decode('utf-8')}")  # Decoding UTF-8 payload
        else:
            print("No NDEF data found.")

    except Exception as e:
        print(f"Error: {e}")


# Call the function
detect_and_read_ndef_record()
