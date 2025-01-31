from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from smartcard.System import readers
import csv
import sys
import pandas as pd


# Function: Write NDEF Text Record to NFC Card
def write_to_nfc_card_as_ndef(ciphertext):
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

        # Create an NDEF Text Record with the ciphertext
        language_code = "en"  # 2-byte language code
        language_code_length = len(language_code)
        ciphertext_length = len(ciphertext)

        # Build the NDEF message
        ndef_message = [
            0x03,  # NDEF TLV type
            ciphertext_length + 7,  # Length of the NDEF message (ciphertext + metadata)
            0xD1,  # NDEF record header (short record, NFC Well Known Type)
            0x01,  # Type length (1 byte, for "T" type)
            ciphertext_length + 3,  # Payload length (ciphertext + language code + status byte)
            0x54,  # Type field ("T" for Text)
            language_code_length,  # Status byte (length of the language code)
        ] + list(language_code.encode("utf-8")) + list(ciphertext) + [0xFE]  # Add terminator TLV

        # Pad NDEF message to align with 4-byte pages
        while len(ndef_message) % 4 != 0:
            ndef_message.append(0x00)

        # Debug: Print the NDEF message
        print(f"Final NDEF message to write: {ndef_message}")
        print(f"Final NDEF message length: {len(ndef_message)} bytes")
        print(f"Ciphertext length being written: {len(ciphertext)} bytes")

        # Write the NDEF message to the NFC card
        page = 4  # Start writing at Address 04
        for i in range(0, len(ndef_message), 4):
            chunk = ndef_message[i:i+4]
            WRITE_COMMAND = [0xFF, 0xD6, 0x00, page, 0x04] + list(chunk)
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


# Function: Parse NDEF Message
def parse_ndef_message(nfc_data):
    """
    Parse NDEF message and extract the ciphertext.
    """
    print(f"Raw NDEF data: {nfc_data.hex()}")

    # Check if NDEF starts with the expected type 0x03
    if nfc_data[0] != 0x03:
        raise ValueError("Invalid NDEF message format.")

    # Length of the NDEF payload
    payload_length = nfc_data[1]
    print(f"NDEF payload length: {payload_length}")

    # Parse NDEF record components
    language_code_length = nfc_data[6]  # Status byte indicates language code length
    ciphertext_start = 7 + language_code_length  # Start of ciphertext
    ciphertext_end = ciphertext_start + (payload_length - (3 + language_code_length))  # End of ciphertext
    ciphertext = nfc_data[ciphertext_start:ciphertext_end]

    # Strip terminator (0xFE) if present at the end
    if ciphertext.endswith(b'\xFE'):
        ciphertext = ciphertext[:-1]

    # Debugging
    print(f"Extracted ciphertext after stripping: {ciphertext.hex()}")
    return ciphertext


# Function: Read from NFC Card
def read_from_nfc_card():
    try:
        # Get the list of available readers
        r = readers()
        if not r:
            print("No NFC readers found.")
            sys.exit(1)

        # Select the first reader
        reader = r[0]
        connection = reader.createConnection()
        connection.connect()

        print(f"NFC card detected using: {reader}")

        # Read raw data from NFC card starting at Address 04
        nfc_data = b""
        for page in range(4, 222):  # Adjust the range based on expected ciphertext size
            READ_COMMAND = [0xFF, 0xB0, 0x00, page, 0x04]
            response, sw1, sw2 = connection.transmit(READ_COMMAND)
            if sw1 == 0x90 and sw2 == 0x00:
                nfc_data += bytes(response)
            else:
                print(f"Failed to read page {page}. SW1: {sw1}, SW2: {sw2}")
                break

        nfc_data = nfc_data.rstrip(b'\x00')  # Remove padding
        print("Successfully read data from NFC card.")

        # Parse NDEF message to extract ciphertext
        return parse_ndef_message(nfc_data)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


# Function: AES Encryption
def aes_encryption_with_ndef(csv_file, output_file="encrypted.bin"):
    # Read the first row of patient data from the CSV file
    df = pd.read_csv(csv_file)
    headers = df.columns.tolist()
    first_row = df.iloc[0].tolist()

    # Convert the patient data to a single string
    data = ",".join(map(str, first_row))

    aes_key = get_random_bytes(16)  # Generate a 16-byte AES key
    cipher = AES.new(aes_key, AES.MODE_OCB)  # Initialize AES in OCB mode
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())  # Encrypt the data

    # Save AES key, tag, and nonce to encrypted.bin
    with open(output_file, "wb") as f:
        f.write(aes_key)  # Save the AES key (16 bytes)
        f.write(tag)  # Save the authentication tag (16 bytes)
        f.write(cipher.nonce)  # Save the nonce (15 bytes)

    print(f"AES key, tag, and nonce saved to '{output_file}'.")

    # Debugging
    print(f"Ciphertext length after encryption: {len(ciphertext)} bytes")

    # Write ciphertext as NDEF Text Record to NFC card
    print("Writing ciphertext to NFC card as NDEF record...")
    write_to_nfc_card_as_ndef(ciphertext)
    print("Ciphertext successfully written to NFC as NDEF Text Record!")

    return headers, aes_key, tag, cipher.nonce, ciphertext



# Function: AES Decryption
def aes_decryption_from_nfc(input_file="encrypted.bin", output_csv="decrypted_aes_data.csv"):
    try:
        # Read AES key, tag, and nonce from encrypted.bin
        with open(input_file, "rb") as f:
            aes_key = f.read(16)  # AES key (16 bytes)
            tag = f.read(16)  # Authentication tag (16 bytes)
            nonce = f.read(15)  # Nonce (15 bytes)

        # Read ciphertext from NFC card
        print("Reading ciphertext from NFC card...")
        ciphertext = read_from_nfc_card()

        # Validate ciphertext length
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        if len(ciphertext) == 0:
            raise ValueError("No ciphertext found on NFC card.")

        # Initialize AES cipher with key and nonce
        cipher = AES.new(aes_key, AES.MODE_OCB, nonce=nonce)

        # Decrypt and verify the ciphertext
        plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()
        print("Decryption successful!")

        # Convert decrypted data back to a list
        decrypted_data = plaintext.split(",")
        print(f"Decrypted data: {decrypted_data}")

        # Write the decrypted data to a CSV file with proper quoting
        with open(output_csv, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            csv_writer.writerow(headers)  # Write the headers
            csv_writer.writerow(decrypted_data)  # Write the decrypted data

        print(f"Decrypted data saved to '{output_csv}'.")

        return decrypted_data

    except ValueError as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)


# Main Function
def main():
    global headers  # Declare headers as global if you want to reuse it across functions (optional)

    # Prompt user for operation
    operation = input("Enter operation ('encryption' or 'decryption'): ").strip().lower()

    if operation == "encryption":
        # Perform encryption and write ciphertext to NFC as NDEF
        csv_file = "sample_patient_data.csv"  # Input CSV file
        headers, aes_key, tag, nonce, ciphertext = aes_encryption_with_ndef(csv_file, output_file="encrypted.bin")

    elif operation == "decryption":
        # Perform decryption and save the plaintext to a CSV file
        if 'headers' not in globals():
            # If headers were not defined (e.g., running decryption without encryption), re-read the headers from CSV
            csv_file = "sample_patient_data.csv"
            df = pd.read_csv(csv_file)
            headers = df.columns.tolist()
        aes_decryption_from_nfc(input_file="encrypted.bin", output_csv="decrypted_aes_data.csv")

    else:
        print("Invalid operation. Please enter 'encryption' or 'decryption'.")


if __name__ == "__main__":
    main()
