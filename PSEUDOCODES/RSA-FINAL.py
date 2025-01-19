Import Libraries:
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import nfc, time, csv

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

Function: Perform RSA Encryption
  Input: data, public_key
  cipher_rsa ← PKCS1_OAEP.new(public_key)
  encrypted_data ← cipher_rsa.encrypt(data)
  Return: encrypted_data

Function: Perform RSA Decryption
  Input: encrypted_data, private_key
  cipher_rsa ← PKCS1_OAEP.new(private_key)
  decrypted_data ← cipher_rsa.decrypt(encrypted_data)
 
Function: NFC Tag Interaction
  Set up NFC reader
  Wait for NFC tag
  If operation = encryption:
    Write encrypted_data to NFC tag
  If operation = decryption:
    Read encrypted_data from NFC tag
  Close NFC connection

Function: Write Decrypted Data to File
  Input: decrypted_data
  Open output_file.csv for writing
  Write decrypted_data to output_file.csv

Main Function:
  operation ← Prompt user: "Generate RSA Keys, Encrypt, or Decrypt?"
  If operation = key generation:
    Generate RSA Keys and save to private.pem and public.pem
  If operation = encryption:
    public_key ← Load RSA Key from public.pem
    data ← Prepare data to be encrypted
    encrypted_data ← Perform RSA Encryption on data with public_key
    Measure encryption_time, memory_usage, throughput
    Write encrypted_data to NFC tag
   
  If operation = decryption:
    private_key ← Load RSA Key from private.pem
    Read encrypted_data from NFC tag
    decrypted_data ← Perform RSA Decryption on encrypted_data with private_key
    Measure decryption_time, memory_usage, throughput
    Write decrypted_data to output_file.csv

Execute Main Function
