import tkinter as tk
from tkinter import ttk, messagebox
import logging
from main import measure_performance, CONFIG_PATH, write_to_nfc_card_as_ndef, read_from_nfc_card
from modules.aes_ndef import aes_encryption, aes_decryption
from modules.aes_rsa import aes_rsa_encryption, aes_rsa_decryption
from modules.rsa import rsa_encryption, rsa_decryption
from modules.hill_cipher import hill_cipher_encryption, hill_cipher_decryption
from modules.ecc import ecc_xor_encryption, ecc_xor_decryption
from modules.ecdh_aes import ecdh_aes_encryption, ecdh_aes_decryption
from smartcard.System import readers

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

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
    
    def build_patient_tab(self):
        ttk.Label(self.patient_tab, text="Select Patient Type:").pack(pady=10)
        self.patient_type = ttk.Combobox(self.patient_tab, values=["New Patient", "Existing Patient"], state="readonly")
        self.patient_type.pack(pady=5)
        self.patient_type.bind("<<ComboboxSelected>>", self.handle_patient_selection)
        
        self.patient_frame = ttk.Frame(self.patient_tab)
        self.patient_frame.pack(pady=10)
    
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
    
    def save_new_patient(self):
        encryption_method = self.encryption_choice.get()
        if not encryption_method:
            messagebox.showerror("Error", "Please select an encryption method.")
            return
        
        patient_data = {field: self.patient_entries[field].get() for field in self.patient_entries}
        encrypted_data = self.encrypt_patient_data(patient_data, encryption_method)
        
        if encrypted_data:
            messagebox.showinfo("Success", "Patient data encrypted and saved successfully!")
        
    def encrypt_patient_data(self, data, method):
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
        
        return encrypt_func(str(data))
    
    def load_existing_patient(self):
        ttk.Label(self.patient_frame, text="Fetching Patient Data...").pack()
        # Assume it reads from NFC and decrypts
        # Placeholder for actual implementation
        
    def build_metrics_tab(self):
        ttk.Label(self.metrics_tab, text="Performance Metrics", font=("Arial", 12, "bold")).pack(pady=10)
        self.metrics_display = tk.Text(self.metrics_tab, height=15, width=80)
        self.metrics_display.pack(pady=10)
    
    def build_nfc_info_tab(self):
        ttk.Label(self.nfc_info_tab, text="NFC Information", font=("Arial", 12, "bold")).pack(pady=10)
        self.nfc_display = tk.Text(self.nfc_info_tab, height=10, width=50)
        self.nfc_display.pack(pady=10)
    
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
