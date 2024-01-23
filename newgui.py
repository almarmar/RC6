import tkinter as tk
from tkinter import Label, Entry, Button, Text, messagebox
import base64

from rc6 import RC6


class RC6GUI:
    def __init__(self, master):
        self.master = master
        master.title("RC6")

        screen_width = master.winfo_screenwidth()
        screen_height = master.winfo_screenheight()
        window_width = 600
        window_height = 400

        x_position = (screen_width - window_width) // 2
        y_position = (screen_height - window_height) // 2

        master.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

        self.label_message = Label(master, text="Сообщение:")
        self.label_message.grid(row=0, column=0, sticky="E")

        self.entry_message = Entry(master, width=50)
        self.entry_message.grid(row=0, column=1, columnspan=2)

        self.label_key = Label(master, text="Ключ:")
        self.label_key.grid(row=1, column=0, sticky="E")

        self.entry_key = Entry(master, width=50)
        self.entry_key.grid(row=1, column=1, columnspan=2)

        self.encrypt_button = Button(master, text="Шифровать", command=self.encrypt)
        self.encrypt_button.grid(row=2, column=0, pady=10)

        self.decrypt_button = Button(master, text="Расшифровать", command=self.decrypt)
        self.decrypt_button.grid(row=2, column=1, pady=10)

        self.label_encrypted_message = Label(master, text="Зашифрованное сообщение:")
        self.label_encrypted_message.grid(row=4, column=0, sticky="E")

        self.entry_encrypted_message = Entry(master, width=50)
        self.entry_encrypted_message.grid(row=4, column=1, columnspan=2)

        self.decrypt_input_button = Button(master, text="Расшифровать введенное", command=self.decrypt_input)
        self.decrypt_input_button.grid(row=5, column=0, columnspan=3, pady=10)

        self.output_text = Text(master, height=10, width=70)
        self.output_text.grid(row=6, column=0, columnspan=3, pady=10)

    def encrypt(self):
        message = self.entry_message.get()
        key = self.entry_key.get()

        cipher = RC6()
        bin_message = cipher.bytesToBin(base64.b64encode(bytes(message, 'utf-8')))
        bin_key = cipher.bytesToBin(base64.b64encode(bytes(key, 'utf-8')))

        self.encrypted_bin_message = cipher.encription(bin_message, bin_key)

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Зашифрованное сообщение: {self.encrypted_bin_message}\n")

    def decrypt(self):
        encrypted_bin_message = self.encrypted_bin_message
        key = self.entry_key.get()

        cipher = RC6()
        bin_message = cipher.bytesToBin(base64.b64encode(bytes(encrypted_bin_message, 'utf-8')))
        bin_key = cipher.bytesToBin(base64.b64encode(bytes(key, 'utf-8')))

        decrypted_bin_message = cipher.decription(bin_message, bin_key)
        decrypted_message = cipher.binToBytes(decrypted_bin_message)

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Расшифрованное сообщение: {decrypted_bin_message}\n")
        self.output_text.insert(tk.END,
                                f"Расшифрованное сообщение (расшифровано): {base64.b64decode(decrypted_message)}")

    def decrypt_input(self):
        encrypted_bin_message = self.entry_encrypted_message.get()
        key = self.entry_key.get()

        cipher = RC6()
        bin_message = cipher.bytesToBin(base64.b64encode(bytes(encrypted_bin_message, 'utf-8')))
        bin_key = cipher.bytesToBin(base64.b64encode(bytes(key, 'utf-8')))

        decrypted_bin_message = cipher.decription(bin_message, bin_key)
        decrypted_message = cipher.binToBytes(decrypted_bin_message)

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Расшифрованное сообщение: {decrypted_bin_message}\n")
        self.output_text.insert(tk.END,
                                f"Расшифрованное сообщение (расшифровано): {base64.b64decode(decrypted_message)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = RC6GUI(root)
    root.mainloop()
