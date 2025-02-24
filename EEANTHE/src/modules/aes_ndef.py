from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pandas as pd

def aes_encryption(get_csv_path, write_to_nfc):
    """Encrypts CSV data with AES and writes to NFC."""
    csv_file = get_csv_path()
    if not csv_file:
        return
    df = pd.read_csv(csv_file)
    first_row = df.iloc[0].tolist()
    data = ",".join(map(str, first_row))
    aes_key = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    write_to_nfc(ciphertext)
    print("AES Encryption completed and written to NFC.")
    
def aes_decryption(read_from_nfc):
    """Decrypts data from NFC using AES."""
    ciphertext = read_from_nfc()
    print("AES Decryption process initiated... (Further implementation required)")
