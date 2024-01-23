import tkinter as tk
from tkinter import ttk
from tkinter import filedialog

from decor import rc6_encrypt, rc6_decrypt


def encrypt():
    word = entry_word.get()
    key = entry_key.get()

    # Encryption
    encrypted_text = rc6_encrypt(word, key)
    label_encrypted.config(text="Encrypted: " + encrypted_text.hex())
    label_decrypted.config(text="Decrypted: ")

    # Update status
    status_label.config(text="Encryption complete")

def decrypt():
    key = entry_key.get()
    encrypted_hex = entry_encrypted_hex.get()

    # Decryption
    try:
        encrypted_text = bytes.fromhex(encrypted_hex)
        decrypted_text = rc6_decrypt(encrypted_text, key)
        label_decrypted.config(text="Decrypted: " + decrypted_text.decode('utf-8'))
        label_encrypted.config(text="Encrypted: ")

        # Update status
        status_label.config(text="Decryption complete")
    except ValueError:
        label_decrypted.config(text="Invalid hexadecimal input")
        label_encrypted.config(text="")
        status_label.config(text="Decryption failed")

def save_result():
    word = entry_word.get()
    key = entry_key.get()
    encrypted_text = label_encrypted.cget("text")[11:]

    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(f"Word: {word}\n")
            file.write(f"Key: {key}\n")
            file.write(f"Encrypted Text: {encrypted_text}")

# GUI setup
root = tk.Tk()
root.title("RC6 Encryption/Decryption")

# Widgets
label_word = ttk.Label(root, text="Слово:")
entry_word = ttk.Entry(root, width=30)

label_key = ttk.Label(root, text="Ключ:")
entry_key = ttk.Entry(root, width=30)

label_encrypted_hex = ttk.Label(root, text="Зашифрованный (шестнадцатеричный):")
entry_encrypted_hex = ttk.Entry(root, width=30)

button_encrypt = ttk.Button(root, text="Шифровать", command=encrypt)
button_decrypt = ttk.Button(root, text="Расшифровать", command=decrypt)
button_save = ttk.Button(root, text="Сохранить результат", command=save_result)

label_encrypted = ttk.Label(root, text="")
label_decrypted = ttk.Label(root, text="")

status_label = ttk.Label(root, text="")

# Layout
label_word.grid(row=0, column=0, padx=10, pady=5, sticky="e")
entry_word.grid(row=0, column=1, padx=10, pady=5)

label_key.grid(row=1, column=0, padx=10, pady=5, sticky="e")
entry_key.grid(row=1, column=1, padx=10, pady=5)

label_encrypted_hex.grid(row=2, column=0, padx=10, pady=5, sticky="e")
entry_encrypted_hex.grid(row=2, column=1, padx=10, pady=5)

button_encrypt.grid(row=3, column=0, pady=10)
button_decrypt.grid(row=3, column=1, pady=10)
button_save.grid(row=4, column=0, columnspan=2, pady=10)

label_encrypted.grid(row=5, column=0, columnspan=2, pady=5)
label_decrypted.grid(row=6, column=0, columnspan=2, pady=5)

status_label.grid(row=7, column=0, columnspan=2, pady=5)

# Run the GUI
root.mainloop()