from __future__ import annotations

import os
from http import HTTPStatus

from django.db import models

import requests
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


class DeviceManager(models.Manager):
    def generate_keys(self) -> tuple[bytes, bytes]:
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key.private_bytes_raw(), public_key.public_bytes_raw()


class Device(models.Model):
    """Records the device information"""

    uuid = models.CharField(max_length=36, unique=True)
    ip = models.GenericIPAddressField(protocol="IPv4", default="0.0.0.0")
    private_key = models.BinaryField()
    public_key = models.BinaryField()
    share_key = models.BinaryField(default=None, null=True)

    objects = DeviceManager()

    def generate_share_key(self, outside_public_key: bytes) -> bytes:
        private_key = x25519.X25519PrivateKey.from_private_bytes(self.private_key)
        public_key = x25519.X25519PublicKey.from_public_bytes(outside_public_key)
        return private_key.exchange(public_key)

    def use_hkdf(self, share_key: bytes) -> tuple[bytes, bytes]:
        """
        example:
            salt = b"rome_random_salt"
            info = b"share_key_encryption"
            kdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=info)
            key_material = kdf.derive(share_key)
            key := 23 bytes, nonce := 16 bytes
            return key_material[:32], key_material[32:48]  # 32 bytes, 16 bytes
        """
        raise NotImplementedError("implemented HKDF not yet")

    def encrypt(self, plaintext: bytes, share_key: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(16)
        algorithm = algorithms.ChaCha20(share_key, nonce=nonce)
        cipher = Cipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, nonce

    def decrypt(self, ciphertext: bytes, share_key: bytes, nonce: bytes) -> bytes:
        algorithm = algorithms.ChaCha20(share_key, nonce=nonce)
        cipher = Cipher(algorithm, mode=None)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    def update_ip(self) -> None:
        response = requests.get("https://checkip.amazonaws.com", timeout=5)
        if response.status_code == HTTPStatus.OK:
            self.ip = response.text.strip()
            self.save()
