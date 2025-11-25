# 🔒 Secure File Exchange: RSA + AES Hybrid Encryption

This document explains the steps and concepts for the secure file exchange protocol demonstrated using a hybrid encryption scheme.

## 🔑 Hybrid Encryption Flow Explanation

The process uses a **hybrid approach** to leverage the strengths of both **symmetric (AES)** and **asymmetric (RSA)** cryptography. 

---

### 1. Preparation (Bob)

Bob generates a unique **RSA public/private key pair**. The **public key** is shared with Alice, while the **private key** remains secret.

### 2. Symmetric Encryption (Alice)

Alice generates a fast, one-time random **AES-256 key** and **IV**. She encrypts the large plaintext file (`alice_message.txt`) using this AES key, creating the ciphertext (`encrypted_file.bin`).

### 3. Asymmetric Key Exchange (Alice)

To securely transmit the AES key (which is small), Alice uses Bob's RSA **public key** to encrypt the AES key, creating the secure key package (`aes_key_encrypted.bin`).

### 4. Transmission

Alice sends the large encrypted file (`encrypted_file.bin`) and the small encrypted key (`aes_key_encrypted.bin`) to Bob.

### 5. Asymmetric Decryption (Bob)

Bob uses his secret RSA **private key** to decrypt the small key package and recover the original **AES key**.

### 6. Symmetric Decryption & Verification (Bob)

Bob uses the recovered AES key and the IV to decrypt the large file, recovering `decrypted_message.txt`. He then computes the **SHA-256 hash** of the recovered file and compares it to the hash of the original file (pre-calculated or sent alongside the data, e.g., in a signed manifest) to ensure **data integrity** and confirm no unauthorized modification occurred during transit.

---

## 📊 Comparison: AES vs. RSA

| Feature | AES (Symmetric) | RSA (Asymmetric/Public Key) |
| :--- | :--- | :--- |
| **Speed** | **Extremely Fast** (especially for large data) | **Very Slow** (computationally intensive) |
| **Use Case** | **Bulk Data Encryption** (files, network traffic) | **Secure Key Exchange** and **Digital Signatures** |
| **Key** | One shared secret key | A pair: Public Key (shared) & Private Key (secret) |
| **Security** | Security relies solely on the secrecy and size of the single key. | Security relies on the complexity of factoring large prime numbers. |

### Conclusion
AES is used for encrypting the large data due to its high speed, and RSA is used for securely transporting the small, secret AES key due to its secure key exchange mechanism.