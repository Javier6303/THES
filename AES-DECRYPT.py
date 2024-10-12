# Import necessary libraries
from Crypto.Cipher import AES
import nfc  
import csv  
import time  


def read_aes_key(file_path):
    # Read the AES key from the bin file.
    
    with open(file_path, "rb") as f:
        aes_key = f.read(16)  # Read the 16-byte AES key
    return aes_key


def aes_decrypt(encrypted_data, aes_key, nonce, tag):
    # Decrypt the encrypted data using the AES key and OCB mode.
    
    cipher = AES.new(aes_key, AES.MODE_OCB, nonce=nonce)  
    try:
        plaintext = cipher.decrypt_and_verify(encrypted_data, tag)  # Decrypt and verify the data
    except ValueError:
        raise Exception("Decryption failed. The message was modified or corrupted.")
    return plaintext.decode()  # Return the decrypted plaintext as a string


def wait_for_nfc_tag():
    # Establish connection to NFC reader and wait for a tag to be tapped.
    
    clf = nfc.ContactlessFrontend('usb')  # Open NFC reader connection
    tag = None
    while not tag:
        # Wait for NFC tag tap
    clf.close()  
    return tag


def read_from_nfc(nfc_tag):
    # Read encrypted data (ciphertext, tag, and nonce) from the NFC card.
    
    if nfc_tag.ndef:
        ndef_message = nfc_tag.ndef.message  
        encrypted_data = bytes(ndef_message[0].data)  # Extract raw bytes from the first NDEF record

        # 1st 16 bytes: tag 
        # Next 15 bytes: nonce 
        # Remaining bytes: ciphertext 

        tag = encrypted_data[:16] 
        nonce = encrypted_data[16:31]  
        ciphertext = encrypted_data[31:]  

        return ciphertext, tag, nonce


def write_to_csv(file_path, decrypted_data):
    # Write the decrypted patient data to a CSV file.
    
    with open(file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        # Write decrypted data as a row


def status_message(success):
    # Display a message indicating whether decryption was successful or not.
    if success:
        print("Decryption successful and data saved to CSV!")
    else:
        print("Decryption failed!")


def aes_decrypt_process(aes_key_file, csv_file_path):
    # AES decryption process and measure decryption time.
    
    aes_key = read_aes_key(aes_key_file)  # Read AES key from the file
    nfc_tag = wait_for_nfc_tag()  # Wait for NFC tag to be tapped

    start_time = time.time()  # Start time for decryption
    ciphertext, tag, nonce = read_from_nfc(nfc_tag)  # Read encrypted data from NFC

    try:
        decrypted_data = aes_decrypt(ciphertext, aes_key, nonce, tag)  # Decrypt the data
        decryption_time = time.time() - start_time  # Calculate decryption time
        print(decryption_time)

        write_to_csv(csv_file_path, decrypted_data)  # Write decrypted data to CSV
        status_message(True) 
    except Exception as e:
        print(e)
        status_message(False)  


def main():
    aes_key_file = 'aes_key.bin'  
    csv_file_path = 'decrypted_data.csv' 
    aes_decrypt_process(aes_key_file, csv_file_path) 


main()
