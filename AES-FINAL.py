Import Libraries:
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time, nfc, csv

Function: Read Data
  Input: file_path
  Open file_path as file
  data ← file content
  Return: data

Function: Generate AES Key
  aes_key ← get_random_bytes(16)
  Save aes_key to key_file.bin
  Return: aes_key

Function: AES Encryption
  Input: data, aes_key
  cipher ← AES.new(aes_key, AES.MODE_OCB)
  ciphertext, tag ← cipher.encrypt_and_digest(data)
  Save encrypted_data, tag, cipher.nonce to encrypted_file.bin
  Return: encrypted_data

Function: AES Decryption
  Input: encrypted_data, aes_key, nonce, tag
  cipher ← AES.new(aes_key, AES.MODE_OCB, nonce=nonce)
  decrypted_data ← cipher.decrypt_and_verify(encrypted_data, tag)
  Return: decrypted_data

Function: NFC Tag Interaction
  Set up NFC reader
  Wait for NFC tag
  If operation = encryption:
    Write encrypted_data to NFC tag
  If operation = decryption:
    Read encrypted_data from NFC tag
  Close NFC connection

Function: Write Decrypted Data
  Input: decrypted_data
  Open output_file.csv for writing
  Write decrypted_data to output_file.csv

Main Function:
operation ← Prompt user: "Encrypt or Decrypt?"
If operation = encryption:
  data ← Read data from data_file.csv
  aes_key ← Generate AES key
  encrypted_data ← Encrypt data with aes_key
  Measure encryption_time, memory_usage, throughput
  Write encrypted_data to NFC tag
If operation = decryption:
  aes_key ← Read AES key from key_file.bin
  encrypted_data ← Read data from NFC tag
  decrypted_data ← Decrypt ciphertext with aes_key
  Measure decryption_time, memory_usage, throughput
  Write decrypted_data to output_file.csv


Execute Main Function
