import tkinter as tk
from tkinter import ttk, messagebox
from main import measure_performance, CONFIG_PATH, write_to_nfc_card_as_ndef, read_from_nfc_card
from modules.aes_ndef import aes_encryption, aes_decryption
from modules.aes_rsa import aes_rsa_encryption, aes_rsa_decryption
from modules.rsa import rsa_encryption, rsa_decryption
from modules.hill_cipher import hill_cipher_encryption, hill_cipher_decryption
from modules.ecc import ecc_xor_encryption, ecc_xor_decryption
from modules.ecdh_aes import ecdh_aes_encryption, ecdh_aes_decryption

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NFC Encryption GUI")
        self.root.geometry("800x600")
        
        # Create a notebook for tabbed interface
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both")
        
        # Create tabs
        self.process_flow_tab = ttk.Frame(self.notebook)
        self.metrics_tab = ttk.Frame(self.notebook)
        self.nfc_info_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.process_flow_tab, text="Encryption Process")
        self.notebook.add(self.metrics_tab, text="Metrics Computation")
        self.notebook.add(self.nfc_info_tab, text="NFC Information")
        
        # Build UI components
        self.build_process_flow_tab()
        self.build_metrics_tab()
        self.build_nfc_info_tab()
    
    def build_process_flow_tab(self):
        ttk.Label(self.process_flow_tab, text="Select Encryption Algorithm:").pack(pady=10)
        self.encryption_choice = ttk.Combobox(self.process_flow_tab, values=["AES", "RSA", "AES-RSA", "Hill Cipher", "ECC XOR", "ECDH-AES"])
        self.encryption_choice.pack(pady=5)
        
        ttk.Label(self.process_flow_tab, text="Select Operation:").pack(pady=10)
        self.operation_choice = ttk.Combobox(self.process_flow_tab, values=["Encryption", "Decryption"])
        self.operation_choice.pack(pady=5)
        
        self.start_button = ttk.Button(self.process_flow_tab, text="Start Process", command=self.start_process)
        self.start_button.pack(pady=20)
        
    def build_metrics_tab(self):
        ttk.Label(self.metrics_tab, text="Performance Metrics", font=("Arial", 12, "bold")).pack(pady=10)
        self.metrics_display = tk.Text(self.metrics_tab, height=10, width=50)
        self.metrics_display.pack(pady=10)
        
    def build_nfc_info_tab(self):
        ttk.Label(self.nfc_info_tab, text="NFC Information", font=("Arial", 12, "bold")).pack(pady=10)
        self.nfc_display = tk.Text(self.nfc_info_tab, height=10, width=50)
        self.nfc_display.pack(pady=10)
        
    def start_process(self):
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
            measure_performance(operation_code, encryption_func, decryption_func, lambda: CONFIG_PATH, write_to_nfc_card_as_ndef, read_from_nfc_card, asymmetric=encryption_method in {"RSA", "AES-RSA", "ECC XOR", "ECDH-AES"})
            messagebox.showinfo("Success", f"{operation} using {encryption_method} completed successfully!")
        else:
            messagebox.showerror("Error", "Please select an encryption method and operation.")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
