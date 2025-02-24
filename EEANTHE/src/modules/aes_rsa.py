from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import pandas as pd

def generate_rsa_keypair():
    """Generate RSA key pair."""
    key = RSA.generate(2048)
    return key.publickey()

def encrypt_with_rsa_aes(get_csv_path, write_to_nfc):
    """Encrypt CSV data using AES, then encrypt the AES key with RSA."""
    csv_file = get_csv_path()
    if not csv_file:
        return
    df = pd.read_csv(csv_file)
    first_row = df.iloc[0].tolist()
    data = ",".join(map(str, first_row))
    rsa_public_key = generate_rsa_keypair()
    aes_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    cipher_aes = AES.new(aes_key, AES.MODE_OCB)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode())
    write_to_nfc(ciphertext)
    print("RSA + AES Encryption completed and written to NFC.")
    
def decrypt_with_rsa_aes(read_from_nfc):
    """Decrypts NFC data using RSA to unlock AES key."""
    ciphertext = read_from_nfc()
    print("RSA + AES Decryption process initiated... (Further implementation required)")
