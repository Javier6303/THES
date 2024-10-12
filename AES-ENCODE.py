# Import necessary libraries
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time
import nfc

def read_csv_file(file_path):
    """
    Open the CSV file and read patient data.
    """
    with open(file_path, 'r') as file:
        # Read CSV and extract relevant patient data
        data = file.read()
    return data


def generate_aes_key():
    """
    Generate a 16-byte AES key and save it for later decryption.
    """
    aes_key = get_random_bytes(16)  # Generate a random AES key
    with open("aes_key.bin", "wb") as f:
        f.write(aes_key)  # Save AES key to a file
    return aes_key


def aes_encrypt(data, aes_key):
    """
    Encrypt the data using AES in OCB mode.
    """
    cipher = AES.new(aes_key, AES.MODE_OCB)  # Initialize AES with OCB mode
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())  # Encrypt the data
    with open("encrypted.bin", "wb") as f:
        f.write(aes_key)  # Save the AES key (for testing/learning)
        f.write(tag)  # Write the tag (for data integrity)
        f.write(cipher.nonce)  # Write the nonce used for encryption
        f.write(ciphertext)  # Write the encrypted data
    return ciphertext, tag, cipher.nonce  # Return encrypted values


def wait_for_nfc_tag():
    """
    Wait for the NFC tag to be tapped and return the tag reference.
    """
    clf = nfc.ContactlessFrontend('usb')  # Open NFC reader connection
    tag = None
    while not tag:
        tag = clf.connect(rdwr={'on-connect': lambda tag: False})  # Wait for NFC tag tap
    clf.close()  # Close NFC connection after use
    return tag


def write_to_nfc(nfc_tag, encrypted_data):
    """
    Write the encrypted data to the NFC card.
    """
    # Assuming `nfc_tag` is a writable NFC tag object
    nfc_tag.ndef.message = encrypted_data  # Write encrypted data to NFC tag


def status_message(success):
    """
    Display a message indicating whether the write was successful or not.
    """
    if success:
        print("Data written to NFC tag successfully!")
    else:
        print("Failed to write data to NFC tag.")


def aes_encrypt_process(data):
    """
    Execute the full AES encryption process and measure encryption time.
    """
    start_time = time.time()  # Start time for encryption
    aes_key = generate_aes_key()  # Generate AES key
    ciphertext, tag, nonce = aes_encrypt(data, aes_key)  # Encrypt the data

    encryption_time = time.time() - start_time  # Calculate encryption time
    print(f"Encryption time: {encryption_time:.4f} seconds")

    nfc_tag = wait_for_nfc_tag()  # Wait for NFC tag to be tapped
    if nfc_tag:
        write_to_nfc(nfc_tag, ciphertext + tag + nonce)  # Write to NFC tag
        status_message(True)  # Success message
    else:
        status_message(False)  # Failure message


def main():
    """
    Main function to handle user interaction and start the encryption process.
    """
    file_path = 'patient_data.csv'  # Path to the CSV file
    data = read_csv_file(file_path)  # Read patient data from CSV file

    # Call the AES encryption process
    aes_encrypt_process(data)


# Call the main function to start the program
main()
