import tkinter as tk
from tkinter import ttk, messagebox
import logging
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from base64 import b64encode, b64decode
from main import measure_performance, CONFIG_PATH, write_to_nfc_card_as_ndef, read_from_nfc_card
from modules.aes_ndef import aes_encryption, aes_decryption
from modules.aes_rsa import aes_rsa_encryption, aes_rsa_decryption
from modules.rsa import rsa_encryption, rsa_decryption
from modules.hill_cipher import hill_cipher_encryption, hill_cipher_decryption
from modules.ecc import ecc_xor_encryption, ecc_xor_decryption
from modules.ecdh_aes import ecdh_aes_encryption, ecdh_aes_decryption
from smartcard.System import readers
from smartcard.util import toHexString

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "encryption_db"
PATIENTS_COLLECTION = "patients"
KEYS_COLLECTION = "keys"

# Connect to MongoDB
try:
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    patients_collection = db[PATIENTS_COLLECTION]
    keys_collection = db[KEYS_COLLECTION]
    logger.info("Connected to MongoDB successfully.")
except Exception as e:
    logger.error(f"Error connecting to MongoDB: {e}")

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NFC Encryption GUI")
        self.root.geometry("800x600")
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both")
        
        self.patient_tab = ttk.Frame(self.notebook)
        self.metrics_tab = ttk.Frame(self.notebook)
        self.nfc_info_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.patient_tab, text="Patient Management")
        self.notebook.add(self.metrics_tab, text="Metrics Computation")
        self.notebook.add(self.nfc_info_tab, text="NFC Information")
        
        self.build_patient_tab()
        self.build_metrics_tab()
        self.build_nfc_info_tab()
    
    def check_nfc_reader(self):
        """Checks if an NFC reader is connected."""
        try:
            r = readers()
            if not r:
                logger.error("No NFC readers found.")
                return False
            return True
        except Exception as e:
            logger.error(f"Error checking NFC readers: {e}")
            return False
            
    def build_patient_tab(self):
        ttk.Label(self.patient_tab, text="Select Patient Type:").pack(pady=10)
        self.patient_type = ttk.Combobox(self.patient_tab, values=["New Patient", "Existing Patient"], state="readonly")
        self.patient_type.pack(pady=5)
        self.patient_type.bind("<<ComboboxSelected>>", self.handle_patient_selection)
        
        self.patient_frame = ttk.Frame(self.patient_tab)
        self.patient_frame.pack(pady=10)
    
    def build_metrics_tab(self):
        ttk.Label(self.metrics_tab, text="Performance Metrics", font=("Arial", 12, "bold")).pack(pady=10)
        self.metrics_display = tk.Text(self.metrics_tab, height=15, width=80)
        self.metrics_display.pack(pady=10)
    
    def handle_patient_selection(self, event):
        for widget in self.patient_frame.winfo_children():
            widget.destroy()
        
        if self.patient_type.get() == "New Patient":
            self.build_new_patient_form()
        else:
            self.load_existing_patient()
    
    def build_new_patient_form(self):
        fields = ["Name", "Address", "Phone Number", "Email"]
        self.patient_entries = {}
        
        for field in fields:
            ttk.Label(self.patient_frame, text=field + ":").pack(pady=5)
            entry = ttk.Entry(self.patient_frame)
            entry.pack(pady=5)
            self.patient_entries[field] = entry
        
        ttk.Label(self.patient_frame, text="Select Encryption Algorithm:").pack(pady=10)
        self.encryption_choice = ttk.Combobox(self.patient_frame, values=["AES", "RSA", "AES-RSA", "Hill Cipher", "ECC XOR", "ECDH-AES"], state="readonly")
        self.encryption_choice.pack(pady=5)
        
        ttk.Button(self.patient_frame, text="Save & Encrypt", command=self.save_new_patient).pack(pady=20)
    
    def save_patient_to_db(self, patient_data, encryption_method, encrypted_data):
        """Saves patient data to MongoDB in the patients collection."""
        patient_data["encryption_method"] = encryption_method
        patient_data["encrypted_data"] = b64encode(encrypted_data).decode()
        patients_collection.insert_one(patient_data)
        logger.info("Patient data saved to MongoDB (patients collection).")
    
    def save_key_to_db(self, key_name, key_data):
        """Saves encryption keys to MongoDB in the keys collection."""
        keys_collection.update_one(
            {"key_name": key_name},
            {"$set": {"key_data": b64encode(key_data).decode()}},
            upsert=True
        )
        logger.info(f"Encryption key '{key_name}' saved to MongoDB (keys collection).")
    

    def save_new_patient(self):
        encryption_method = self.encryption_choice.get()
        if not encryption_method:
            messagebox.showerror("Error", "Please select an encryption method.")
            return
        
        patient_data = {field: self.patient_entries[field].get() for field in self.patient_entries}
        encrypted_data = self.encrypt_patient_data(patient_data, encryption_method, write_to_nfc_card_as_ndef)
        
        if not encrypted_data:
            messagebox.showerror("Error", "Encryption failed.")
            return
        
        # Ensure NFC writing was successful before saving keys
        success = write_to_nfc_card_as_ndef(encrypted_data)
        if not success:
            messagebox.showerror("Error", "No NFC reader detected or failed to write to NFC card. Keys will NOT be saved.")
            return  # Prevent storing keys in MongoDB
        
        self.store_patient_in_db(patient_data, encryption_method, encrypted_data)
        messagebox.showinfo("Success", "Patient data encrypted, saved, and written to NFC successfully!")

    def encrypt_patient_data(self, data, method, write_to_nfc):
        encryption_methods = {
            "AES": aes_encryption,
            "RSA": rsa_encryption,
            "AES-RSA": aes_rsa_encryption,
            "Hill Cipher": hill_cipher_encryption,
            "ECC XOR": ecc_xor_encryption,
            "ECDH-AES": ecdh_aes_encryption
        }
        encrypt_func = encryption_methods.get(method)
        if not encrypt_func:
            messagebox.showerror("Error", "Invalid encryption method selected.")
            return None
        
        return encrypt_func(data, write_to_nfc)
    
    def load_existing_patient(self):
        """Loads an existing patient's encrypted data from the NFC card and decrypts it."""
        if not self.check_nfc_reader():
            messagebox.showerror("Error", "No NFC reader detected.")
            return
        
        encrypted_data = read_from_nfc_card()
        if not encrypted_data:
            messagebox.showerror("Error", "Failed to read data from NFC card.")
            return
        
        patient_record = patients_collection.find_one({"encrypted_data": b64encode(encrypted_data).decode()})
        if not patient_record:
            messagebox.showerror("Error", "No matching patient record found in the database.")
            return
        
        encryption_method = patient_record.get("encryption_method")
        key_record = keys_collection.find_one({"key_name": encryption_method})
        
        if not key_record:
            messagebox.showerror("Error", "Encryption key not found in database.")
            return
        
        decryption_methods = {
            "AES": aes_decryption,
            "RSA": rsa_decryption,
            "AES-RSA": aes_rsa_decryption,
            "Hill Cipher": hill_cipher_decryption,
            "ECC XOR": ecc_xor_decryption,
            "ECDH-AES": ecdh_aes_decryption
        }
        decrypt_func = decryption_methods.get(encryption_method)
        
        if not decrypt_func:
            messagebox.showerror("Error", "Invalid decryption method.")
            return
        
        decrypted_data = decrypt_func(patient_record["encrypted_data"], key_record["key_data"])
        if not decrypted_data:
            messagebox.showerror("Error", "Decryption failed.")
            return
        
        fields = ["Name", "Address", "Phone Number", "Email"]
        self.patient_entries = {}
        
        for i, field in enumerate(fields):
            ttk.Label(self.patient_frame, text=field + ":").pack(pady=5)
            entry = ttk.Entry(self.patient_frame)
            entry.insert(0, decrypted_data.split(",")[i])
            entry.pack(pady=5)
            self.patient_entries[field] = entry
        
        ttk.Button(self.patient_frame, text="Update", command=lambda: self.save_existing_patient(decrypted_data)).pack(pady=20)
    

    def build_nfc_info_tab(self):
        def refresh_nfc_info():
            if not self.check_nfc_reader():
                self.nfc_display.delete("1.0", tk.END)
                self.nfc_display.insert(tk.END, "No NFC reader detected.")
                return
            
            try:
                r = readers()
                if not r:
                    self.nfc_display.delete("1.0", tk.END)
                    self.nfc_display.insert(tk.END, "No NFC reader detected.")
                    return
                
                reader = r[0]
                connection = reader.createConnection()
                connection.connect()
                atr = toHexString(connection.getATR())
                
                # Read UID
                GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
                response, sw1, sw2 = connection.transmit(GET_UID)
                uid = toHexString(response) if sw1 == 0x90 and sw2 == 0x00 else "UID UNAVAILABLE"
                
                # Read memory information
                MEMORY_INFO_COMMAND = [0xFF, 0xB0, 0x00, 0x02, 0x04]
                response, sw1, sw2 = connection.transmit(MEMORY_INFO_COMMAND)
                memory_info = toHexString(response) if sw1 == 0x90 and sw2 == 0x00 else "UNKNOWN"
                
                # Check if protected by password
                PASSWORD_PROTECTION_COMMAND = [0xFF, 0xB0, 0x00, 0xE3, 0x04]  # Read AUTH0 byte
                response, sw1, sw2 = connection.transmit(PASSWORD_PROTECTION_COMMAND)
                protected_by_password = "Yes" if response[0] != 0xFF else "No"
                
                nfc_data = read_from_nfc_card()
                if not nfc_data:
                    nfc_data = "Failed to read NFC card."
                
                self.nfc_display.delete("1.0", tk.END)
                GET_TECH = [0xFF, 0xB0, 0x00, 0x00, 0x04]  # Command to get tech info (placeholder, may vary by card type)
                response, sw1, sw2 = connection.transmit(GET_TECH)
                tech_info = toHexString(response) if sw1 == 0x90 and sw2 == 0x00 else "UNKNOWN"
                self.nfc_display.insert(tk.END, f"TECH: {tech_info}")
                self.nfc_display.insert(tk.END, f"UID: {uid}\n")
                self.nfc_display.insert(tk.END, f"ATR: {atr}\n")
                self.nfc_display.insert(tk.END, f"MEMORY INFORMATION: {memory_info}\n")
                self.nfc_display.insert(tk.END, f"PROTECTED BY PASSWORD: {protected_by_password}\n")
                self.nfc_display.insert(tk.END, f"RECORD 1: {nfc_data}\n")
            except Exception as e:
                self.nfc_display.delete("1.0", tk.END)
                self.nfc_display.insert(tk.END, f"Error reading NFC card: {e}")
        
        ttk.Label(self.nfc_info_tab, text="NFC Information", font=("Arial", 12, "bold")).pack(pady=10)
        self.nfc_display = tk.Text(self.nfc_info_tab, height=15, width=60)
        self.nfc_display.pack(pady=10)
        ttk.Button(self.nfc_info_tab, text="Refresh NFC Info", command=refresh_nfc_info).pack(pady=10)
    
    
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
