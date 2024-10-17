Import Libraries:
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import nfc, time

Function: Read Data
  Input: file_path
  Open file_path as file
  data ← file content
  Return: data

Function: Generate RSA Keys
  rsa_key_pair ← Generate new RSA key pair
  Save rsa_key_pair.private_key to private.pem
  Save rsa_key_pair.public_key to public.pem

Function: Load RSA Key
  Input: key_type
  If key_type = public:
    Load public_key from public.pem
  If key_type = private:
    Load private_key from private.pem
  Return: public_key or private_key

Function: Perform RSA+AES Hybrid Encryption
  Input: plaintext, public_key
  aes_key ← get_random_bytes(16)
  cipher_rsa ← PKCS1_OAEP.new(public_key)
  enc_aes_key ← cipher_rsa.encrypt(aes_key)
  cipher_aes ← AES.new(aes_key, AES.MODE_OCB)
  ciphertext, tag ← cipher_aes.encrypt_and_digest(plaintext)
  Save enc_aes_key, cipher_aes.nonce, and tag to binary_file.bin
  Return: ciphertext

Function: Perform RSA+AES Hybrid Decryption
  Read enc_aes_key, nonce, and tag from binary_file.bin
  Input: ciphertext, private_key
  cipher_rsa ← PKCS1_OAEP.new(private_key)
  aes_key ← cipher_rsa.decrypt(enc_aes_key)
  cipher_aes ← AES.new(aes_key, AES.MODE_OCB, nonce=nonce)
  decrypted_data ← cipher_aes.decrypt_and_verify(ciphertext, tag)
  Return: decrypted_data

Function: NFC Tag Interaction
  Set up NFC reader
  Wait for NFC tag
  If operation = encryption:
    Write ciphertext to NFC tag
  If operation = decryption:
    Read ciphertext from NFC tag
  Close NFC connection

Function: Write Decrypted Data to File
  Input: decrypted_data
  Open output_file.csv for writing
  Write decrypted_data to output_file.csv

Main Function
operation ← Prompt user: "Generate RSA Keys, Encrypt, or Decrypt?"
If operation = key generation:
  Generate RSA Keys and save to private.pem and public.pem
If operation = encryption:
  public_key ← Load RSA Key from public.pem
  data ← Read data from data_file.csv
  ciphertext ← Perform RSA+AES Hybrid Encryption on data with public_key
  Measure encryption_time, memory_usage, throughput
  Write enc_aes_key, nonce, and tag to binary_file.bin
  Write ciphertext to NFC tag
  Display "Encryption successful" or "Encryption failed"
If operation = decryption:
  private_key ← Load RSA Key from private.pem
  Read enc_aes_key, nonce, and tag from binary_file.bin
  Read ciphertext from NFC tag
  decrypted_data ← Perform RSA+AES Hybrid Decryption on ciphertext with private_key
  Measure decryption_time, memory_usage, throughput
  Write decrypted_data to output_file.csv
  Display "Decryption successful" or "Decryption failed"

Execute Main Function
