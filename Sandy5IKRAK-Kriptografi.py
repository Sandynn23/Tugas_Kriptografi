from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from os import urandom
import base64


print("=========================================================================================================")
print("NAMA : Sandy Nikma Nasokha")
print("Kelas : 5IKRA")
print("=========================================================================================================")

# Fungsi untuk menghasilkan kunci simetris dari password
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    key = kdf.derive(password.encode())
    return key

# Fungsi untuk enkripsi pesan
def encrypt_message(key: bytes, plaintext: str) -> (bytes, bytes):
    iv = urandom(16)  # Inisialisasi vektor (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding agar sesuai dengan blok AES 16 byte
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext

# Fungsi untuk dekripsi pesan
def decrypt_message(key: bytes, iv: bytes, ciphertext: bytes) -> str:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Menghapus padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# Fungsi untuk pengirim (enkripsi pesan)
def sender_mode():
    # Input password dan pesan dari pengguna
    password = input("Pengirim - Masukkan password yang digunakan untuk enkripsi: ")
    plaintext = input("Pengirim - Masukkan pesan yang ingin dikirim: ")
    
    print("\nPesan asli:", plaintext)

    # Membuat salt dan menghasilkan kunci simetris
    salt = urandom(16)
    key = generate_key(password, salt)

    # Enkripsi pesan
    iv, ciphertext = encrypt_message(key, plaintext)
    
    # Gabungkan salt, IV, dan ciphertext
    encrypted_data = salt + iv + ciphertext
    encrypted_b64 = base64.b64encode(encrypted_data).decode()

    # Simpan ciphertext asli ke file
    with open("ciphertext.txt", "w") as f:
        f.write(encrypted_b64)

    # Membatasi ciphertext menjadi hanya 6 karakter
    short_ciphertext = encrypted_b64[:6]

    print("\nCiphertext (terenkripsi, salin dan kirim ini ke penerima):")
    print(short_ciphertext)

# Fungsi untuk penerima (dekripsi pesan)
def receiver_mode():
    # Input password dan ciphertext dari penerima
    password = input("Penerima - Masukkan password yang digunakan untuk dekripsi: ")
    short_ciphertext = input("Penerima - Masukkan ciphertext yang diterima (paste di sini, 6 huruf): ")

    # Membaca ciphertext dari file
    try:
        with open("ciphertext.txt", "r") as f:
            stored_ciphertext = f.read()
    except FileNotFoundError:
        print("Error: Tidak ada pesan terenkripsi yang tersedia. Pastikan pengirim telah mengenkripsi pesan.")
        return

    # Gunakan ciphertext asli dari file
    encrypted_data = base64.b64decode(stored_ciphertext)

    # Pisahkan salt, IV, dan ciphertext
    salt = encrypted_data[:16]  # Salt 16 byte
    iv = encrypted_data[16:32]  # IV 16 byte
    ciphertext = encrypted_data[32:]  # Sisanya adalah ciphertext

    # Menghasilkan kunci dari password dan salt
    key = generate_key(password, salt)

    # Dekripsi pesan
    decrypted_message = decrypt_message(key, iv, ciphertext)
    print("\nPesan yang didekripsi:", decrypted_message)

# Program utama
def main():
    mode = input("Pilih mode: [1] Pengirim, [2] Penerima: ")
    if mode == "1":
        sender_mode()
    elif mode == "2":
        receiver_mode()
    else:
        print("Pilihan tidak valid.")

if __name__ == "__main__":
    main()
