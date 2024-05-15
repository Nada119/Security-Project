import hashlib
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, DES
from Crypto import Random


# AES Cipher class
class AESCipher:
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        encrypted_data = iv + encrypted_text
        return b64encode(encrypted_data).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_data = b64decode(encrypted_text)
        iv = encrypted_data[: self.block_size]
        encrypted_text = encrypted_data[self.block_size :]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = decrypted_text.decode("utf-8")
        return self.__unpad(decrypted_text)

    def __pad(self, plain_text):
        pad_length = self.block_size - len(plain_text) % self.block_size
        padding = chr(pad_length) * pad_length
        return plain_text + padding

    def __unpad(self, decrypted_text):
        pad_length = ord(decrypted_text[-1])
        return decrypted_text[:-pad_length]


# DES Cipher class
class DESCipher:
    def __init__(self, key):
        self.block_size = DES.block_size
        self.key = self.__adjust_key(key)

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        encrypted_data = iv + encrypted_text
        return b64encode(encrypted_data).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_data = b64decode(encrypted_text)
        iv = encrypted_data[: self.block_size]
        encrypted_text = encrypted_data[self.block_size :]
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = decrypted_text.decode("utf-8")
        return self.__unpad(decrypted_text)

    def __adjust_key(self, key):
        if len(key) < 8:
            key += b"0" * (8 - len(key))
        elif len(key) > 8:
            key = key[:8]
        return key

    def __pad(self, plain_text):
        pad_length = self.block_size - len(plain_text) % self.block_size
        padding = chr(pad_length) * pad_length
        return plain_text + padding

    def __unpad(self, decrypted_text):
        pad_length = ord(decrypted_text[-1])
        return decrypted_text[:-pad_length]
