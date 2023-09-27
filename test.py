import base64
import os
import tkinter as tk
from tkinter import ttk

import passphrase as passphrase
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
import json
import hashlib
import keyAPI
from base64 import b64encode, b64decode

def check_saved_data():
    try:
        with open("users.json", "r") as file:
            data = json.load(file)
            print("Data in users.json:", data)
    except FileNotFoundError:
        print("The file 'users.json' does not exist.")
    except json.JSONDecodeError as e:
        print("Error decoding JSON:", str(e))


def calculate_key_id(key_data):
    # Calculate a key ID, for example, by hashing the key data (you can customize this)
    # Here, we use SHA-256 as an example
    sha256 = hashlib.sha256()
    sha256.update(key_data)
    return sha256.hexdigest()


class KeyGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PGP Key Generator")

        self.users = []
        self.user_keys = []  # Dictionary to store user keys

        self.frame = ttk.Frame(root, padding=10)
        self.frame.grid(row=0, column=0)

        ttk.Label(self.frame, text="User Name:").grid(row=0, column=0)
        self.name_entry = ttk.Entry(self.frame)
        self.name_entry.grid(row=0, column=1)

        ttk.Button(self.frame, text="Add User", command=self.add_user).grid(row=0, column=2)

        self.user_selector = ttk.Combobox(self.frame, values=["Select User"])
        self.user_selector.grid(row=0, column=3)
        self.user_selector.set("Select User")
        self.user_selector.bind("<<ComboboxSelected>>", self.on_user_select)

        ttk.Label(self.frame, text="Algorithm:").grid(row=1, column=0)
        self.algorithm_selector = ttk.Combobox(self.frame, values=["RSA", "DSA+ElGamal"])
        self.algorithm_selector.grid(row=1, column=1)
        self.algorithm_selector.set("RSA")

        ttk.Label(self.frame, text="Key Size (bits):").grid(row=1, column=2)
        self.key_size_entry = ttk.Entry(self.frame)
        self.key_size_entry.grid(row=1, column=3)
        self.key_size_entry.insert(0, "2048")  # Default key size

        ttk.Button(self.frame, text="Generate Keys", command=self.generate_keys).grid(row=1, column=4)

        self.result_label = ttk.Label(self.frame, text="", foreground="green")
        self.result_label.grid(row=2, columnspan=5)

        # Add a border around the Treeview
        self.tree_frame = ttk.Frame(self.root, borderwidth=1, relief="solid")
        self.tree_frame.grid(row=1, column=0, columnspan=6, sticky="nsew")

        self.tree = ttk.Treeview(self.tree_frame, columns=("User", "Private Key", "Public Key"), show="headings")
        self.tree.heading("User", text="User")
        self.tree.heading("Private Key", text="Private Key")
        self.tree.heading("Public Key", text="Public Key")
        self.tree.pack(side="left", fill="both", expand=True)

        self.tree_scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.tree_scrollbar.set)
        self.tree_scrollbar.pack(side="right", fill="y")

        # Configure row and column weights to make the Treeview expand
        root.grid_rowconfigure(1, weight=1)
        root.grid_columnconfigure(0, weight=1)

        # Load user information and keys from a JSON file if it exists
        self.load_users()

    def add_user(self):
        user_name = self.name_entry.get()
        if user_name and user_name not in self.users:
            self.users.append(user_name)
            self.user_selector['values'] = ["Select User"] + self.users
            self.user_selector.set(user_name)
            self.name_entry.delete(0, 'end')
            self.result_label.config(text=f"User {user_name} added.")
            # Save user information to the JSON file
            self.save_users()

    def generate_keys(self):
        user_name = self.user_selector.get()
        algorithm = self.algorithm_selector.get()
        key_size = int(self.key_size_entry.get())

        if user_name != "Select User":
            passphrase = "your_passphrase_here"  # Set user-specific passphrase here

            # Check if directories exist, and create them if not
            if not os.path.exists("PrivateKeys"):
                os.makedirs("PrivateKeys")
            if not os.path.exists("PublicKeys"):
                os.makedirs("PublicKeys")

            # Load the existing private key data (if it exists)
            private_key_file_name = f"PrivateKeys/{user_name}Private.pem"
            existing_private_key_data = None

            if os.path.isfile(private_key_file_name):
                with open(private_key_file_name, "rb") as private_key_file:
                    existing_private_key_data = private_key_file.read()

            if algorithm == "RSA":
                # Generate a new private key
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size,
                    backend=default_backend()
                )

                # Serialize the new private key to PEM format
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
                )

                # If existing_private_key_data is not None, append the new private key data
                if existing_private_key_data:
                    private_pem = existing_private_key_data + private_pem

                # Save the private key to the user-specific file with the user's name
                with open(private_key_file_name, "wb") as private_key_file:
                    private_key_file.write(private_pem)

                # Serialize the public key to PEM format
                public_key = private_key.public_key()
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                # Save the public key to a user-specific file
                public_key_file_name = f"PublicKeys/{user_name}Public.pem"
                with open(public_key_file_name, "ab") as public_key_file:  # Use 'ab' for append mode
                    public_key_file.write(public_pem)

                # Create a key ID for the user's private key (for example, SHA-256 hash of the key)
                key_id = calculate_key_id(private_pem)

                # Append the new key information to the list of user_keys
                self.user_keys.append({
                    'User Name': user_name,
                    'Key ID': key_id,
                    'Private Key': private_key_file_name,
                    'Public Key': public_key_file_name
                })

                # Update the Treeview to show the user's keys
                self.update_treeview(user_name)

                self.result_label.config(text=f"Keys generated for {user_name}.")
            elif algorithm == "DSA+ElGamal":
                pass
                # DSA+ElGamal key generation logic

                # Generate DSA private key
                # dsa_private_key = dsa.generate_private_key(
                #     key_size=key_size,
                #     backend=default_backend()
                # )
                #
                # # Generate ElGamal private key
                # elgamal_private_key = elgamal.generate_private_key(
                #     key_size=key_size,
                #     backend=default_backend()
                # )
                #
                # # Combine DSA and ElGamal private keys into a single private key
                # private_key = dsa_private_key.private_bytes(
                #     encoding=serialization.Encoding.PEM,
                #     format=serialization.PrivateFormat.PKCS8,
                #     encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
                # ) + elgamal_private_key.private_bytes(
                #     encoding=serialization.Encoding.PEM,
                #     format=serialization.PrivateFormat.PKCS8,
                #     encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
                # )
                #
                # # If existing_private_key_data is not None, append the new private key data
                # if existing_private_key_data:
                #     private_key = existing_private_key_data + private_key
                #
                # # Save the private key to the user-specific file with the user's name
                # with open(private_key_file_name, "wb") as private_key_file:
                #     private_key_file.write(private_key)
                #
                # # Serialize the public key to PEM format
                # dsa_public_key = dsa_private_key.public_key()
                # elgamal_public_key = elgamal_private_key.public_key()
                # public_key = dsa_public_key.public_bytes(
                #     encoding=serialization.Encoding.PEM,
                #     format=serialization.PublicFormat.SubjectPublicKeyInfo
                # ) + elgamal_public_key.public_bytes(
                #     encoding=serialization.Encoding.PEM,
                #     format=serialization.PublicFormat.SubjectPublicKeyInfo
                # )
                #
                # # Save the public key to a user-specific file
                # public_key_file_name = f"PublicKeys/{user_name}Public.pem"
                # with open(public_key_file_name, "ab") as public_key_file:  # Use 'ab' for append mode
                #     public_key_file.write(public_key)
                #
                # # Create a key ID for the user's private key (for example, SHA-256 hash of the key)
                # key_id = calculate_key_id(private_key)
                #
                # # Append the new key information to the list of user_keys
                # self.user_keys.append({
                #     'User Name': user_name,
                #     'Key ID': key_id,
                #     'Private Key': private_key_file_name,
                #     'Public Key': public_key_file_name
                # })
                #
                # # Update the Treeview to show the user's keys
                # self.update_treeview(user_name)
                #
                # self.result_label.config(text=f"Keys generated for {user_name}.")
            else:
                self.result_label.config(text="Invalid algorithm selection.")
                return

    # Make sure to use this updated version of the generate_keys function in your code.

    def on_user_select(self, event):
        user_name = self.user_selector.get()
        if user_name != "Select User":
            self.update_treeview(user_name)
        else:
            self.tree.delete(*self.tree.get_children())

    # def load_users(self):
    #     try:
    #         with open("users.json", "r") as file:
    #             users_data = json.load(file)
    #             self.users = users_data.get('users', [])
    #             self.user_selector['values'] = ["Select User"] + self.users
    #             # Load user keys and key IDs from the PEM files
    #             for user_name in self.users:
    #                 private_key_file_name = f"PrivateKeys/{user_name}Private.pem"
    #                 if os.path.isfile(private_key_file_name):
    #                     with open(private_key_file_name, "rb") as private_key_file:
    #                         private_pem = private_key_file.read()
    #                         key_id = calculate_key_id(private_pem)
    #                         public_key_file_name = f"PublicKeys/{user_name}Public.pem"
    #                         # Append the user keys as a list of dictionaries
    #                         self.user_keys.append({
    #                             'User Name': user_name,
    #                             'Key ID': key_id,
    #                             'Private Key': private_key_file_name,
    #                             'Public Key': public_key_file_name
    #                         })
    #     except FileNotFoundError:
    #         self.users = []

    def load_users(self):
        try:
            with open("users.json", "r") as file:
                users_data = json.load(file)
                self.users = users_data.get('users', [])
                self.user_selector['values'] = ["Select User"] + self.users
                # Load user keys and key IDs from the PEM files
                for user_name in self.users:
                    private_key_file_name = f"PrivateKeys/{user_name}Private.pem"
                    if os.path.isfile(private_key_file_name):
                        with open(private_key_file_name, "rb") as private_key_file:
                            private_pems = private_key_file.read().split(b'-----END PRIVATE KEY-----\n')
                            for private_pem in private_pems:
                                if private_pem.strip():
                                    key_id = calculate_key_id(private_pem)
                                    public_key_file_name = f"PublicKeys/{user_name}Public.pem"
                                    # Append each user key as a dictionary
                                    self.user_keys.append({
                                        'User Name': user_name,
                                        'Key ID': key_id,
                                        'Private Key': private_key_file_name,
                                        'Public Key': public_key_file_name
                                    })
        except FileNotFoundError:
            self.users = []

    def save_users(self):
        data = {"users": self.users}
        try:
            with open("users.json", "w") as file:
                json.dump(data, file)
        except Exception as e:
            print("An error occurred:", str(e))

    def update_treeview(self, user_name):
        # Clear the Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Find all keys for the selected user
        user_keys = [user for user in self.user_keys if user['User Name'] == user_name]

        # Insert each key into the Treeview
        for keys in user_keys:
            private_key_file = keys.get('Private Key', '')
            public_key_file = keys.get('Public Key', '')
            key_id = keys.get('Key ID', '')

            # Insert user name, key ID, and file names into the Treeview
            self.tree.insert("", "end", values=(user_name, key_id, private_key_file, public_key_file))

        # Refresh the Treeview to ensure proper rendering
        self.tree.update()


if __name__ == "__main__":
    # root = tk.Tk()
    # app = KeyGeneratorApp(root)
    # root.grid_columnconfigure(0, weight=1)  # Expand column 0 horizontally
    # root.mainloop()

    #sha-1 odradjen tacno
    zdravo = keyAPI.sha1_hash("zdravo")

    #generisanje rsa kljuca i  potpisa
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_str = private_key_pem.decode('utf-8')
    private_key_str = '\n'.join(private_key_str.split('\n')[1:-2])

    potpis = keyAPI.potpis(zdravo, private_key)

    print(potpis)

    #potpis pretvaram u string i konkateniram sa originalnom porukom

    potpis_str = b64encode(potpis).decode('utf-8')
    print(potpis_str)

    conc = potpis_str + "zdravo"

    #zipovanje fajla
    zipovanStringByte = keyAPI.compress_string(conc)
    zipovanString = b64encode(zipovanStringByte).decode('utf-8')
    print(zipovanStringByte)
    print(zipovanString)

    #tajnost poruke(enkriptovanje poruke koriscenjem sesijskog kljuca i algoritme AES ili 3DES)
    tajnost, session_key, iv, sa = keyAPI.tajnost(zipovanString, "AES128") #sa je koji je algoritam
    tajnost_string = b64encode(tajnost).decode('utf-8')
    print(tajnost)

    #enkripcija session_key sa tudjim public kljucem
    private_key2 = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    public_key2 = private_key2.public_key()

    enkriptovan_skey = keyAPI.encrypt_session_key_with_public_key(session_key, public_key2)
    enkriptovan_skey_string = b64encode(enkriptovan_skey).decode('utf-8')
    print(enkriptovan_skey)
    print(enkriptovan_skey_string)

    #krajnja poruka koja se salje
    EC = tajnost_string + enkriptovan_skey_string
    EP = enkriptovan_skey_string

    #kreiranje fajla
    filename = "kraj.txt"
    file = open(filename, "w")

