from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
import base64
import pandas as pd
import csv


# ------------------- ECC KEY GENERATION -------------------

def generate_ecc_key_pair(private_key_file="ecc_private.pem", public_key_file="ecc_ephemeral_public.pem"):
    """Generate ECC Private-Public Key Pair and save the private key."""
    private_key = ec.generate_private_key(ec.SECP256R1())

    with open(private_key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"ECC private key saved to '{private_key_file}'.")

    return private_key, private_key.public_key()

# ------------------- ECC + XOR ENCRYPTION -------------------

def ecc_xor_encryption(get_csv_path, write_to_nfc, private_key_file="ecc_private.pem", public_key_file="ecc_ephemeral_public.pem"):
    """Encrypt CSV data using ECC XOR encryption and write to NFC."""
    csv_file = get_csv_path()
    if not csv_file:
        return

    df = pd.read_csv(csv_file)
    first_row = df.iloc[0].tolist()
    plaintext = ",".join(map(str, first_row))

    private_key, public_key = generate_ecc_key_pair(private_key_file, public_key_file)

    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=len(plaintext),
        salt=None,
        info=b"ecc-xor-key"
    ).derive(shared_secret)

    encrypted_bytes = bytes(a ^ b for a, b in zip(plaintext.encode(), derived_key))
    encrypted_text = base64.b64encode(encrypted_bytes).decode()

    print("Writing ciphertext to NFC card...")
    write_to_nfc(encrypted_text.encode("utf-8"))
    print("Ciphertext successfully written to NFC!")

    # Save the ephemeral public key
    with open(public_key_file, "wb") as f:
        f.write(ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Ephemeral public key saved to '{public_key_file}'.")

# ------------------- ECC + XOR DECRYPTION -------------------

def ecc_xor_decryption(get_csv_path, read_from_nfc, private_key_file="ecc_private.pem", public_key_file="ecc_ephemeral_public.pem", output_file="decrypted_ecc_data.csv"):
    """Decrypt data from NFC using ECC XOR encryption and restore CSV format."""
    try:
        with open(private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        with open(public_key_file, "rb") as f:
            ephemeral_public_key = serialization.load_pem_public_key(f.read())

        encrypted_text = read_from_nfc().decode("utf-8")

        if not encrypted_text:
            print("Error: No ciphertext found on NFC card.")
            return

        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

        encrypted_bytes = base64.b64decode(encrypted_text)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=len(encrypted_bytes),
            salt=None,
            info=b"ecc-xor-key"
        ).derive(shared_secret)

        decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_bytes, derived_key))
        decrypted_text = decrypted_bytes.decode()

        decrypted_data = decrypted_text.split(",")

        csv_file = get_csv_path()
        if not csv_file:
            return

        df = pd.read_csv(csv_file)
        headers = df.columns.tolist()

        if len(headers) != len(decrypted_data):
            decrypted_data = decrypted_data[:len(headers)]

        with open(output_file, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
            csv_writer.writerow(headers)
            csv_writer.writerow(decrypted_data)

        print(f"Decrypted data saved to '{output_file}'.")

    except Exception as e:
        print(f"Decryption failed: {e}")
