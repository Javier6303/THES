import tkinter as tk
from tkinter import ttk, messagebox
import logging
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from base64 import b64encode
from modules.aes_ndef import aes_encryption
from modules.aes_rsa import aes_rsa_encryption
from modules.rsa import rsa_encryption
from modules.hill_cipher import hill_cipher_encryption
from modules.ecc import ecc_xor_encryption
from modules.ecdh_aes import ecdh_aes_encryption
from main import write_to_nfc_card_as_ndef
from modules.db_manager import save_new_patient

# ----------------- LOGGER -----------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------------- LOAD ENV -----------------
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "encryption_db"
PATIENTS_COLLECTION = "patients"

# ----------------- CONNECT TO MONGO -----------------
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
patients_collection = db[PATIENTS_COLLECTION]


# ----------------- GUI CLASS -----------------
class EncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("New Patient Encryption")
        self.root.geometry("900x700")

        ttk.Label(root, text="Select Patient Type:").pack(pady=5)
        self.patient_type = ttk.Combobox(root, values=["New Patient"], state="readonly")
        self.patient_type.set("New Patient")
        self.patient_type.pack(pady=5)

        self.patient_fields = ["Name", "Age", "Sex", "Address", "Contact Number", "Email", "Birthday", "Height",
                                "Blood Pressure", "Blood Type", "Allergies", "History of Medical Illnesses",
                                "Doctor's Notes", "Last Appointment Date"]
        self.entries = {}

        for field in self.patient_fields:
            ttk.Label(root, text=field.capitalize() + ":").pack(pady=3)
            entry = ttk.Entry(root)
            entry.pack(pady=3)
            self.entries[field] = entry

        ttk.Label(root, text="Select Encryption Algorithm:").pack(pady=5)
        self.encryption_choice = ttk.Combobox(
            root,
            values=["AES", "RSA", "AES-RSA", "Hill Cipher", "ECC XOR", "ECDH-AES"],
            state="readonly"
        )
        self.encryption_choice.pack(pady=5)

        self.save_btn = ttk.Button(root, text="Save & Encrypt", command=self.save_and_encrypt)
        self.save_btn.pack(pady=20)

    def save_and_encrypt(self):
        # Validate selection
        method = self.encryption_choice.get()
        if not method:
            messagebox.showerror("Error", "Please select an encryption method.")
            return

        # Extract patient data
        patient_data = {field: self.entries[field].get().strip() for field in self.patient_fields}
        if any(not value for value in patient_data.values()):
            messagebox.showerror("Error", "All patient fields must be filled.")
            return

        patient_id = save_new_patient(patient_data)
        logger.info(f"New patient saved to MongoDB with ID {patient_id}")

        # Call encryption
        encryption_func = {
            "AES": aes_encryption,
            "RSA": rsa_encryption,
            "AES-RSA": aes_rsa_encryption,
            "Hill Cipher": hill_cipher_encryption,
            "ECC XOR": ecc_xor_encryption,
            "ECDH-AES": ecdh_aes_encryption
        }.get(method)

        try:
            encrypted_data = encryption_func(patient_id, write_to_nfc_card_as_ndef)
            if not encrypted_data:
                raise Exception("Encryption failed or patient not found.")

            logger.info("Encryption and NFC write complete.")
            messagebox.showinfo("Success", f"Patient data encrypted and written to NFC.\nPatient ID: {patient_id}")

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            messagebox.showerror("Encryption Error", str(e))


# ----------------- LAUNCH -----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionGUI(root)
    root.mainloop()
