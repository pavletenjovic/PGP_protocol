import hashlib
import tempfile

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import io
import zipfile

import secrets
from base64 import b64encode, b64decode


def sha1_hash(input_string):
    sha1 = hashlib.sha1()
    sha1.update(input_string.encode('utf-8'))
    return sha1.hexdigest()


def potpis(message, private_key):
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def compress_string(message):
    compressed_data = io.BytesIO()

    with zipfile.ZipFile(compressed_data, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr('data.txt', message)

    compressed_content = compressed_data.getvalue()
    return compressed_content


def tajnost(message, algoritam):
    if algoritam == "AES128":
        session_key = secrets.token_bytes(16)
        # Generate a random IV (Initialization Vector)
        iv = secrets.token_bytes(16)

        # Create an AES cipher with the session key and IV
        cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))

        encryptor = cipher.encryptor()

        # Encrypt the message
        encrypted_data = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

        # Combine IV and encrypted data
        combined_data = iv + encrypted_data

        return combined_data, session_key, iv, "aes128"

    elif algoritam == "3DES":
        session_key = secrets.token_bytes(24)

        # Generate a random IV (Initialization Vector)
        iv = secrets.token_bytes(8)

        cipher = Cipher(algorithms.TripleDES(session_key), modes.CFB(iv))

        encryptor = cipher.encryptor()

        # Encrypt the message
        encrypted_data = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

        # Combine IV and encrypted data
        combined_data = iv + encrypted_data

        return combined_data, session_key, iv, "3des"


def encrypt_session_key_with_public_key(session_key, public_key):
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_session_key


def get_least_significant_bits(pubkey1):
    mask = (1 << 64) - 1  # Create a bitmask with 'num_bits' set to 1
    return pubkey1.n & mask


def get_most_significant_bits(number):
    mask = (1 << 16) - 1
    most_significant_bits = number >> 15
    return most_significant_bits & mask


def decrypt_with_rsa(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')


def decrypt_with_session_key(session_key, iv, encrypted_data, type):
    if type == "AES128":
        # Ensure session_key is bytes
        session_key = session_key.encode('utf-8')

        # Create an AES cipher with the session key and IV
        cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))

        # Create a decryptor
        decryptor = cipher.decryptor()

        # Decrypt the encrypted data
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Create an unpadder
        unpadder = padding.PKCS7(128).unpadder()

        # Unpad the decrypted data
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        return decrypted_data.decode('utf-8')
    elif type == "3DES":
        session_key = session_key.encode('utf-8')

        # Create a Triple DES cipher with the session key and IV
        cipher = Cipher(algorithms.TripleDES(session_key), modes.CFB(iv))

        # Create a decryptor
        decryptor = cipher.decryptor()

        # Decrypt the encrypted data
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Create an unpadder
        unpadder = padding.PKCS7(64).unpadder()

        # Unpad the decrypted data
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        return decrypted_data.decode('utf-8')


def decompress_zip_bytes(compressed_data):
    input_buffer = io.BytesIO(compressed_data)
    output_dir = tempfile.mkdtemp()  # Create a temporary directory

    with zipfile.ZipFile(input_buffer, 'r') as zipf:
        zipf.extractall(output_dir)

    # Read the extracted file
    extracted_file_path = zipf.namelist()[0]
    with open(output_dir + '/' + extracted_file_path, 'rb') as extracted_file:
        decompressed_bytes = extracted_file.read()

    return decompressed_bytes
