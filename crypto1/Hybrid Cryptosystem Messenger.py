import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # KEEP ASYMMETRIC PADDING HERE
from cryptography.hazmat.primitives import hashes
# IMPORT symmetric padding separately:
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization


# --- STEP 1: Initialization ---
def generate_message_file(filepath="message.txt",
                          content="The secret to a secure connection is to use a hybrid cryptosystem."):
    """Creates the initial plaintext message file."""
    with open(filepath, "wb") as f:
        f.write(content.encode('utf-8'))
    print(f"[INIT] Created plaintext message in: {filepath}")
    return content


# --- STEP 2: RSA Key Generation (User A) ---
def generate_rsa_key_pair():
    """Generates RSA private and public keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    print("[A] RSA key pair generated.")
    return private_key, public_key


# --- STEP 3: Symmetric Encryption (User B) ---
def encrypt_message_with_aes(message_bytes, output_file="encrypted_message.bin"):
    """
    Generates a random AES-256 key and IV, and encrypts the message.
    Returns the raw AES key for subsequent RSA encryption.
    """
    # Generate a random 256-bit AES key and a random 128-bit Initialization Vector (IV)
    aes_key = os.urandom(32)  # 256 bits for AES-256
    iv = os.urandom(16)  # 128 bits for CBC mode

    # Initialize the AES cipher
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Encrypt the data, ensuring it is padded to the block size (AES uses 16 bytes/128 bits)
    # We use PKCS7 padding as AES requires data to be a multiple of the block size.
    padder = PKCS7(algorithms.AES.block_size).padder()  # FIX: Use PKCS7 imported from the correct location
    padded_data = padder.update(message_bytes) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Write the encrypted message and the IV (needed for decryption) to the output file
    # IV must be known to the receiver but does not need to be secret.
    with open(output_file, "wb") as f:
        f.write(iv + ciphertext)

    print(f"[B] Message encrypted with AES-256 and saved to: {output_file}")
    print(f"[B] Generated AES Key (32 bytes): {aes_key.hex()[:8]}...")

    return aes_key


# --- STEP 4: RSA Encryption of the AES Key (User B) ---
def encrypt_aes_key_with_rsa(aes_key, rsa_public_key, output_file="aes_key_encrypted.bin"):
    """Encrypts the AES key using User A's RSA public key."""
    # Use OAEP padding for optimal security with RSA encryption
    encrypted_key = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_file, "wb") as f:
        f.write(encrypted_key)

    print(f"[B] AES Key encrypted with RSA and saved to: {output_file}")
    return encrypted_key


# --- STEP 5: RSA Decryption of the AES Key (User A) ---
def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
    """Decrypts the AES key using User A's RSA private key."""
    decrypted_key = rsa_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"[A] AES Key successfully decrypted.")
    return decrypted_key


# --- STEP 6: Symmetric Decryption (User A) ---
def decrypt_message_with_aes(aes_key, input_file="encrypted_message.bin", output_file="decrypted_message.txt"):
    """Decrypts the message using the recovered AES key."""
    with open(input_file, "rb") as f:
        data = f.read()

    # Extract the IV (first 16 bytes) and the ciphertext
    iv = data[:16]
    ciphertext = data[16:]

    # Initialize the AES cipher for decryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the message
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()  # FIX: Use PKCS7 imported from the correct location
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Write the final plaintext message to a file
    with open(output_file, "wb") as f:
        f.write(plaintext)

    print(f"[A] Message decrypted with AES-256 and saved to: {output_file}")
    print(f"[A] Decrypted Message: \"{plaintext.decode('utf-8')}\"")
    return plaintext


# --- MAIN EXECUTION FLOW ---
def run_hybrid_messenger():
    # 1. SETUP: Create the initial message file
    message = generate_message_file()
    message_bytes = message.encode('utf-8')

    # 2. USER A (Receiver) generates keys
    rsa_private_key, rsa_public_key = generate_rsa_key_pair()

    # --- TRANSMISSION START (User B prepares the package) ---

    # 3. USER B (Sender) encrypts the message with AES
    aes_key = encrypt_message_with_aes(message_bytes)

    # 4. USER B (Sender) encrypts the AES key with A's public RSA key
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, rsa_public_key)

    # --- TRANSMISSION COMPLETE (User A receives encrypted files) ---

    # 5. USER A (Receiver) decrypts the AES key with their private RSA key
    decrypted_aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key)

    # 6. USER A (Receiver) decrypts the message with the recovered AES key
    decrypt_message_with_aes(decrypted_aes_key)

    print("\n[SUCCESS] Hybrid Encryption/Decryption flow completed.")


if __name__ == "__main__":
    # Ensure the cryptography library is installed: pip install cryptography
    run_hybrid_messenger()