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
        
        self.encryption_process = ttk.Frame(self.notebook)
        self.metrics_tab = ttk.Frame(self.notebook)
        self.nfc_info_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.encryption_process, text="Encryption Process")
        self.notebook.add(self.metrics_tab, text="Metrics Computation")
        self.notebook.add(self.nfc_info_tab, text="NFC Information")
        
        self.build_encryption_process()
        self.build_metrics_tab()
        self.build_nfc_info_tab()
    
    def build_encryption_process(self):
        ttk.Label(self.encryption_process, text="Select Encryption Algorithm:").pack(pady=10)
        self.encryption_choice = ttk.Combobox(self.encryption_process, values=["AES", "RSA", "AES-RSA", "Hill Cipher", "ECC XOR", "ECDH-AES"])
        self.encryption_choice.pack(pady=5)
        
        ttk.Label(self.encryption_process, text="Select Operation:").pack(pady=10)
        self.operation_choice = ttk.Combobox(self.encryption_process, values=["Encryption", "Decryption"])
        self.operation_choice.pack(pady=5)
        
        self.start_button = ttk.Button(self.encryption_process, text="Start Process", command=self.start_process)
        self.start_button.pack(pady=20)
        
    def build_metrics_tab(self):
        ttk.Label(self.metrics_tab, text="Performance Metrics", font=("Arial", 12, "bold")).pack(pady=10)
        self.metrics_display = tk.Text(self.metrics_tab, height=15, width=80)
        self.metrics_display.pack(pady=10)
        
    def build_nfc_info_tab(self):
        ttk.Label(self.nfc_info_tab, text="NFC Information", font=("Arial", 12, "bold")).pack(pady=10)
        self.nfc_display = tk.Text(self.nfc_info_tab, height=10, width=50)
        self.nfc_display.pack(pady=10)
    
    def check_nfc_card(self):
        try:
            r = readers()
            return len(r) > 0
        except Exception:
            return False
        
    def start_process(self):
        if not self.check_nfc_card():
            messagebox.showerror("Error", "No NFC card detected. Please place an NFC card on the reader.")
            return
        
        encryption_method = self.encryption_choice.get()
        operation = self.operation_choice.get()
        encryption_methods = {
            "AES": (aes_encryption, aes_decryption),
            "RSA": (rsa_encryption, rsa_decryption),
            "AES-RSA": (aes_rsa_encryption, aes_rsa_decryption),
            "Hill Cipher": (hill_cipher_encryption, hill_cipher_decryption),
            "ECC XOR": (ecc_xor_encryption, ecc_xor_decryption),
            "ECDH-AES": (ecdh_aes_encryption, ecdh_aes_decryption)
        }
        
        if encryption_method and operation:
            encryption_func, decryption_func = encryption_methods.get(encryption_method, (None, None))
            if not encryption_func or not decryption_func:
                messagebox.showerror("Error", "Invalid encryption method selected.")
                return
            
            operation_code = "1" if operation == "Encryption" else "2"
            logger.info(f"Starting {operation} using {encryption_method}...")
            
            try:
                metrics = measure_performance(operation_code, encryption_func, decryption_func, lambda: CONFIG_PATH, write_to_nfc_card_as_ndef, read_from_nfc_card, asymmetric=encryption_method in {"RSA", "AES-RSA", "ECC XOR", "ECDH-AES"})
                
                self.metrics_display.delete("1.0", tk.END)
                self.metrics_display.insert(tk.END, f"Metrics:\n{metrics}\n")
                
                messagebox.showinfo("Success", f"{operation} using {encryption_method} completed successfully!")
                logger.info(f"{operation} completed successfully. Metrics: {metrics}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")
                logger.error(f"Error during {operation}: {e}", exc_info=True)
        else:
            messagebox.showerror("Error", "Please select an encryption method and operation.")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()