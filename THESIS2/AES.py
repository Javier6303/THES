from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from smartcard.System import readers
import sys


# Function: Write to NFC Card
def write_to_nfc_card(ciphertext):
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

        # Create the raw message (ciphertext as bytes)
        message_bytes = ciphertext
        while len(message_bytes) % 4 != 0:  # Pad to align with 4-byte NFC pages
            message_bytes += b'\x00'

        # Write the message to the NFC card
        page = 4  # Start writing at Address 04
        for i in range(0, len(message_bytes), 4):
            chunk = message_bytes[i:i+4]
            WRITE_COMMAND = [0xFF, 0xD6, 0x00, page, 0x04] + list(chunk)
            response, sw1, sw2 = connection.transmit(WRITE_COMMAND)
            if sw1 == 0x90 and sw2 == 0x00:
                print(f"Successfully wrote to page {page}: {chunk.hex()}")
                page += 1
            else:
                print(f"Failed to write to page {page}. SW1: {sw1}, SW2: {sw2}")
                break

        print("Write operation complete.")

    except Exception as e:
        print(f"Error: {e}")


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
        ciphertext = b""
        for page in range(4, 222):  # Adjust the range based on ciphertext size
            READ_COMMAND = [0xFF, 0xB0, 0x00, page, 0x04]
            response, sw1, sw2 = connection.transmit(READ_COMMAND)
            if sw1 == 0x90 and sw2 == 0x00:
                ciphertext += bytes(response)
            else:
                print(f"Failed to read page {page}. SW1: {sw1}, SW2: {sw2}")
                break

        # Remove padding (zeros)
        ciphertext = ciphertext.rstrip(b'\x00')
        print("Successfully read ciphertext from NFC card.")
        return ciphertext

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


# Function: AES Encryption
def aes_encryption(data, output_file="encrypted.bin"):
    aes_key = get_random_bytes(16)  # Generate a 16-byte AES key
    cipher = AES.new(aes_key, AES.MODE_OCB)  # Initialize AES in OCB mode
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())  # Encrypt the data

    # Save AES key, tag, and nonce to encrypted.bin
    with open(output_file, "wb") as f:
        f.write(aes_key)  # Save the AES key (16 bytes)
        f.write(tag)  # Save the authentication tag (16 bytes)
        f.write(cipher.nonce)  # Save the nonce (15 bytes)

    print(f"AES key, tag, and nonce saved to '{output_file}'.")

    # Write ciphertext to NFC card
    print("Writing ciphertext to NFC card...")
    write_to_nfc_card(ciphertext)
    print("Ciphertext successfully written to NFC!")

    return aes_key, tag, cipher.nonce, ciphertext


# Function: AES Decryption
def aes_decryption(input_file="encrypted.bin", output_file="decrypted_aes.txt"):
    try:
        # Read AES key, tag, and nonce from encrypted.bin
        with open(input_file, "rb") as f:
            aes_key = f.read(16)  # AES key (16 bytes)
            tag = f.read(16)  # Authentication tag (16 bytes)
            nonce = f.read(15)  # Nonce (15 bytes)

        # Read ciphertext from NFC card
        print("Reading ciphertext from NFC card...")
        ciphertext = read_from_nfc_card()

        # Initialize AES cipher with key and nonce
        cipher = AES.new(aes_key, AES.MODE_OCB, nonce=nonce)

        # Decrypt and verify the ciphertext
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print("Decryption successful!")

        # Save plaintext to a file
        with open(output_file, "w") as f:
            f.write(plaintext.decode())
        print(f"Decrypted plaintext saved to '{output_file}'.")

        return plaintext

    except ValueError:
        print("Decryption failed: The message was modified or the tag is incorrect.")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)


# Main Function
def main():
    # Prompt user for operation
    operation = input("Enter operation ('encryption' or 'decryption'): ").strip().lower()

    if operation == "encryption":
        # Read plaintext data from the user
        plaintext = input("Enter the plaintext to encrypt: ").strip()

        # Perform encryption and write ciphertext to NFC
        aes_encryption(plaintext, output_file="encrypted.bin")

    elif operation == "decryption":
        # Perform decryption and save the plaintext to a file
        aes_decryption(input_file="encrypted.bin", output_file="decrypted_aes.txt")

    else:
        print("Invalid operation. Please enter 'encryption' or 'decryption'.")


if __name__ == "__main__":
    main()
