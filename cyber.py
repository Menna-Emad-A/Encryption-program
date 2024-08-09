import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import numpy as np
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

class AESCipher(object):
    def init(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        print("The plain text after padding: ", padded_plain_text)
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]

import string

def key_generation(key):
    # initializing all and generating key_matrix
    main=string.ascii_lowercase.replace('j','.')
    # convert all alphabets to lower
    key=key.lower()
    
    key_matrix=['' for i in range(5)]
    # if we have spaces in key, those are ignored automatically
    i=0;j=0
    for c in key:
        if c in main:
            # putting into matrix
            key_matrix[i]+=c

            # to make sure repeated characters in key
            # doesnt include in the key_matrix, we replace the
            # alphabet into . in the main, whenever comes in iteration
            main=main.replace(c,'.')
            # counting column change
            j+=1
            # if column count exceeds 5
            if(j>4):
                # row count is increased
                i+=1
                # column count is set again to zero
                j=0

    # to place other alphabets in the key_matrix
    # the i and j values returned from the previous loop
    # are again used in this loop, continuing the values in them
    for c in main:
        if c!='.':
            key_matrix[i]+=c

            j+=1
            if j>4:
                i+=1
                j=0
                
    return key_matrix


def encrypt(plaintext, key):
    key_matrix = key_generation(key)

    def encryption(plain_text):
        # seggrigating the maeesage into pairs
        plain_text_pairs=[]
        # replacing repeated characters in pair with other letter, x
        cipher_text_pairs=[]

        # remove spaces
        plain_text=plain_text.replace(" ","")
        # convert to lower case
        plain_text=plain_text.lower()

        # RULE1: if both letters in the pair are same or one letter is left at last,
        # replace second letter with x or add x, else continue with normal pairing

        i=0
        # let plain_text be abhi
        while i<len(plain_text):
            # i=0,1,2,3
            a=plain_text[i]
            b=''

            if((i+1)==len(plain_text)):
                # if the chosen letter is last and doesnt have pair
                # then the pai will be x
                b='x'
            else:
                # else the next letter will be pair with the previous letter
                b=plain_text[i+1]

            if(a!=b):
                plain_text_pairs.append(a+b)
                # if not equal then leave the next letter,
                # as it became pair with previous alphabet
                i+=2
            else:
                plain_text_pairs.append(a+'x')
                # else dont leave the next letter and put x
                # in place of repeated letter and conitnue with the next letter
                # which is repeated (according to algo)
                i+=1
                
        print("plain text pairs: ",plain_text_pairs)


        for pair in plain_text_pairs:
            # RULE2: if the letters are in the same row, replace them with
            # letters to their immediate right respectively
            flag=False
            for row in key_matrix:
                if(pair[0] in row and pair[1] in row):
                    # find will return index of a letter in string
                    j0=row.find(pair[0])
                    j1=row.find(pair[1])
                    cipher_text_pair=row[(j0+1)%5]+row[(j1+1)%5]
                    cipher_text_pairs.append(cipher_text_pair)
                    flag=True
            if flag:
                continue

            # RULE3: if the letters are in the same column, replace them with
            # letters to their immediate below respectively
                    
            for j in range(5):
                col="".join([key_matrix[i][j] for i in range(5)])
                if(pair[0] in col and pair[1] in col):
                    # find will return index of a letter in string
                    i0=col.find(pair[0])
                    i1=col.find(pair[1])
                    cipher_text_pair=col[(i0+1)%5]+col[(i1+1)%5]
                    cipher_text_pairs.append(cipher_text_pair)
                    flag=True
            if flag:
                continue
            #RULE:4 if letters are not on the same row or column,
            # replace with the letters on the same row respectively but
            # at the other pair of corners of rectangle,
            # which is defined by the original pair

            i0=0
            i1=0
            j0=0
            j1=0

            for i in range(5):
                row=key_matrix[i]
                if(pair[0] in row):
                    i0=i
                    j0=row.find(pair[0])
                if(pair[1] in row):
                    i1=i
                    j1=row.find(pair[1])
            cipher_text_pair=key_matrix[i0][j1]+key_matrix[i1][j0]
            cipher_text_pairs.append(cipher_text_pair)
            
        print("cipher text pairs: ",cipher_text_pairs)
        # final statements
        print('plain text: ',plain_text)
        print('cipher text: ',"".join(cipher_text_pairs))
        return "".join(cipher_text_pairs)

    return encryption(plaintext)

def decrypt(ciphertext, key):
    key_matrix = key_generation(key)

    def conversion(cipher_text):
        # seggrigating the maeesage into pairs
        plain_text_pairs = []
        # replacing repeated characters in pair with other letter, x
        cipher_text_pairs = []

        # convert to lower case
        cipiher_text = cipher_text.lower()

        # RULE1: if both letters in the pair are same or one letter is left at last,
        # replace second letter with x or add x, else continue with normal pairing

        i = 0
        while i < len(cipher_text):
            # i=0,1,2,3
            a = cipher_text[i]
            b = cipher_text[i + 1]

            cipher_text_pairs.append(a + b)
            # else dont leave the next letter and put x
            # in place of repeated letter and conitnue with the next letter
            # which is repeated (according to algo)
            i += 2

        print("cipher text pairs: ", cipher_text_pairs)

        for pair in cipher_text_pairs:
            # RULE2: if the letters are in the same row, replace them with
            # letters to their immediate right respectively
            flag = False
            for row in key_matrix:
                if pair[0] in row and pair[1] in row:
                    # find will return index of a letter in string
                    j0 = row.find(pair[0])
                    j1 = row.find(pair[1])
                    # same as reverse
                    # instead of -1 we are doing +4 as it is modulo 5
                    plain_text_pair = row[(j0 + 4) % 5] + row[(j1 + 4) % 5]
                    plain_text_pairs.append(plain_text_pair)
                    flag = True
            if flag:
                continue

            # RULE3: if the letters are in the same column, replace them with
            # letters to their immediate below respectively

            for j in range(5):
                col = "".join([key_matrix[i][j] for i in range(5)])
                if pair[0] in col and pair[1] in col:
                    # find will return index of a letter in string
                    i0 = col.find(pair[0])
                    i1 = col.find(pair[1])
                    # same as reverse
                    # instead of -1 we are doing +4 as it is modulo 5
                    plain_text_pair = col[(i0 + 4) % 5] + col[(i1 + 4) % 5]
                    plain_text_pairs.append(plain_text_pair)
                    flag = True
            if flag:
                continue
            # RULE:4 if letters are not on the same row or column,
            # replace with the letters on the same row respectively but
            # at the other pair of corners of rectangle,
            # which is defined by the original pair

            i0 = 0
            i1 = 0
            j0 = 0
            j1 = 0

            for i in range(5):
                row = key_matrix[i]
                if pair[0] in row:
                    i0 = i
                    j0 = row.find(pair[0])
                if pair[1] in row:
                    i1 = i
                    j1 = row.find(pair[1])
            plain_text_pair = key_matrix[i0][j1] + key_matrix[i1][j0]
            plain_text_pairs.append(plain_text_pair)

        print("plain text pairs: ", plain_text_pairs)
        # final statements

        print('cipher text: ', "".join(cipher_text_pairs))
        print('plain text (message): ', "".join(plain_text_pairs))
        return "".join(plain_text_pairs)

    return conversion(ciphertext)

def hill_cipher(text, key, decrypt=False):
    if len(text) % len(key) != 0:
        raise ValueError("Plaintext length must be a multiple of the key matrix size")
    key_size = len(key)
    text = text.upper().replace(" ", "")
    text_length = len(text)
    result = ""
    if decrypt:
        key = matrix_mod_inv(key, 26)
    for i in range(0, text_length, key_size):
        block = np.array([ord(char) - ord("A") for char in text[i:i+key_size]])
        if decrypt:
            block = np.dot(key, block)
        else:
            block = np.dot(key, block)
        result += "".join([chr(char % 26 + ord("A")) for char in block])
    return result

def matrix_mod_inv(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = mod_inverse(det, modulus)
    if det_inv is None:
        raise ValueError("The determinant is not invertible")
    adjugate = (det * np.linalg.inv(matrix)).astype(int)
    return (det_inv * adjugate) % modulus

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def caesar_cipher(text, key, decrypt=False):
    result = ""
    for char in text:
        if char.isalpha():
            shift = key if not decrypt else -key
            shift %= 26
            if char.islower():
                result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            result += char
    return result

def rot1(text, decrypt=False):
    result = ""
    shift = -1 if decrypt else 1
    for char in text:
        if char.isalpha():
            if char.islower():
                result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            result += char
    return result

def rot13(text, decrypt=False):
    result = ""
    shift = -13 if decrypt else 13
    for char in text:
        if char.isalpha():
            if char.islower():
                result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            result += char
    return result

def affine_cipher(text, a, b, decrypt=False):
    if decrypt:
        a_inv = mod_inverse(a, 26)
        if a_inv is None:
            return "Error: Invalid key. 'a' value is not invertible."
        result = ""
        for char in text:
            if char.isalpha():
                if char.islower():
                    result += chr(((a_inv * (ord(char) - ord('a') - b)) % 26) + ord('a'))
                else:
                    result += chr(((a_inv * (ord(char) - ord('A') - b)) % 26) + ord('A'))
            else:
                result += char
        return result
    else:
        result = ""
        for char in text:
            if char.isalpha():
                if char.islower():
                    result += chr(((a * (ord(char) - ord('a')) + b) % 26) + ord('a'))
                else:
                    result += chr(((a * (ord(char) - ord('A')) + b) % 26) + ord('A'))
            else:
                result += char
        return result

# GUI

def encrypt_decrypt():
    mode = mode_var.get()
    plaintext = plaintext_entry.get("1.0", tk.END).strip()
    ciphertext = ciphertext_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()

    if mode == "Encrypt":
        algorithm = algorithm_var.get()
        if algorithm == "Playfair Cipher":
            ciphertext = encrypt(plaintext, key)
        elif algorithm == "Hill Cipher":
            key_values = list(map(int, key.split()))
            key_size = int(len(key_values) ** 0.5)
            key_matrix = np.array(key_values).reshape((key_size, key_size))
            ciphertext = hill_cipher(plaintext, key_matrix)
        elif algorithm == "Caesar Cipher":
            try:
                key_int = int(key)
                ciphertext = caesar_cipher(plaintext, key_int)
            except ValueError:
                ciphertext = "Invalid key. Please enter an integer value for the Caesar Cipher key."
        elif algorithm == "Affine Cipher":
            try:
                a, b = key.split()
                a_int, b_int = int(a), int(b)
                ciphertext = affine_cipher(plaintext, a_int, b_int)
            except ValueError:
                ciphertext = "Invalid key. Please enter two integers separated by a space for the Affine Cipher key."
        elif algorithm == "ROT13":  
            ciphertext = rot13(plaintext)
        elif algorithm == "ROT1":  
            ciphertext = rot1(plaintext)
        elif algorithm == "AES":
            cipher = AESCipher(key)
            ciphertext = cipher.encrypt(plaintext)
        else:
            ciphertext = "Invalid algorithm selected"

        ciphertext_entry.delete("1.0", tk.END)
        ciphertext_entry.insert(tk.END, ciphertext)
    elif mode == "Decrypt":
        algorithm = algorithm_var.get()
        if algorithm == "Playfair Cipher":
            decrypted_text = decrypt(ciphertext, key)
        elif algorithm == "Hill Cipher":
            key_values = list(map(int, key.split()))
            key_size = int(len(key_values) ** 0.5)
            key_matrix = np.array(key_values).reshape((key_size, key_size))
            decrypted_text = hill_cipher(ciphertext, key_matrix, decrypt=True)
        elif algorithm == "Caesar Cipher":
            try:
                key_int = int(key)
                decrypted_text = caesar_cipher(ciphertext, key_int, decrypt=True)
            except ValueError:
                decrypted_text = "Invalid key. Please enter an integer value for the Caesar Cipher key."
        elif algorithm == "Affine Cipher":
            try:
                a, b = key.split()
                a_int, b_int = int(a), int(b)
                decrypted_text = affine_cipher(ciphertext, a_int, b_int, decrypt=True)
            except ValueError:
                decrypted_text = "Invalid key. Please enter two integers separated by a space for the Affine Cipher key."
        elif algorithm == "ROT13":  
            decrypted_text = rot13(ciphertext, decrypt=True)
        elif algorithm == "ROT1":  
            decrypted_text = rot1(ciphertext, decrypt=True)
        elif algorithm == "AES":
            cipher = AESCipher(key)
            decrypted_text = cipher.decrypt(ciphertext)
        else:
            decrypted_text = "Invalid algorithm selected"

        plaintext_entry.delete("1.0", tk.END)
        plaintext_entry.insert(tk.END, decrypted_text)

def save_text(entry_widget):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", ".txt"), ("All Files", ".*")])
    if file_path:
        content = entry_widget.get("1.0", tk.END)
        with open(file_path, "w") as file:
            file.write(content)
        messagebox.showinfo("Save Successful", "The text has been successfully saved.")

def reset_fields():
    plaintext_entry.delete("1.0", tk.END)
    ciphertext_entry.delete("1.0", tk.END)
    key_entry.delete(0, tk.END)

root = tk.Tk()
root.title("Encryption/Decryption Tool")
root.geometry("700x429")  

style = ttk.Style()
style.theme_use("clam")

plaintext_label = ttk.Label(root, text="Plaintext:")
plaintext_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
ciphertext_label = ttk.Label(root, text="Ciphertext:")
ciphertext_label.grid(row=0, column=2, padx=10, pady=5, sticky="w")
key_label = ttk.Label(root, text="Key:")
key_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
algorithm_label = ttk.Label(root, text="Algorithm:")
algorithm_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")

plaintext_entry = tk.Text(root, height=10, width=30)
plaintext_entry.grid(row=1, column=0, padx=10, pady=5, sticky="w")
ciphertext_entry = tk.Text(root, height=10, width=30)
ciphertext_entry.grid(row=1, column=2, padx=10, pady=5, sticky="w")
key_entry = ttk.Entry(root)
key_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

algorithm_var = tk.StringVar(root)
algorithm_choices = ["Caesar Cipher", "ROT13", "ROT1", "Affine Cipher", "Hill Cipher", "Playfair Cipher", "AES"]
algorithm_dropdown = ttk.Combobox(root, textvariable=algorithm_var, values=algorithm_choices, state="readonly",
                                  width=20)
algorithm_dropdown.grid(row=3, column=1, padx=10, pady=5, sticky="w")
algorithm_dropdown.current(0)

mode_var = tk.StringVar(root, "Encrypt")
encrypt_radio = ttk.Radiobutton(root, text="Encrypt", variable=mode_var, value="Encrypt")
encrypt_radio.grid(row=4, column=0, padx=10, pady=5, sticky="w")
decrypt_radio = ttk.Radiobutton(root, text="Decrypt", variable=mode_var, value="Decrypt")
decrypt_radio.grid(row=4, column=2, padx=10, pady=5, sticky="w")

process_button = ttk.Button(root, text="Process", command=encrypt_decrypt)
process_button.grid(row=5, column=1, padx=10, pady=10, sticky="we")

#load_plaintext_button = ttk.Button(root, text="Load Plaintext", command=lambda: load_text(plaintext_entry))
#load_plaintext_button.grid(row=6, column=0, padx=10, pady=5, sticky="we")

save_ciphertext_button = ttk.Button(root, text="Save Ciphertext", command=lambda: save_text(ciphertext_entry))
save_ciphertext_button.grid(row=6, column=2, padx=10, pady=5, sticky="we")

save_plaintext_button = ttk.Button(root, text="Save Plaintext", command=lambda: save_text(plaintext_entry))
save_plaintext_button.grid(row=6, column=0, padx=10, pady=5, sticky="we")

reset_button = ttk.Button(root, text="Reset", command=reset_fields)
reset_button.grid(row=6, column=1, padx=10, pady=5, sticky="we")

root.mainloop()