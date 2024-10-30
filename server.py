import socket  # Untuk komunikasi jaringan menggunakan UDP
import threading  # Untuk menjalankan beberapa proses sekaligus
import queue  # Untuk membuat antrian pesan
import time  # Untuk mengatur timestamp pesan
import os  # Untuk cek keberadaan file
import hashlib  # Untuk enkripsi dan integritas data

# Kunci enkripsi yang digunakan oleh client dan server untuk RC4
SHARED_KEY = b'my_shared_rc4_key'

# Fungsi RC4 untuk mengenkripsi dan mendekripsi data dengan kunci tertentu
def rc4(key, data):
    S = list(range(256))  # Inisialisasi array S dengan angka 0 hingga 255
    j = 0
    out = []

    # Permutasi kunci RC4 (Key-Scheduling Algorithm)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    # Proses enkripsi/dekripsi dengan RC4 (Pseudo-Random Generation Algorithm)
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    return bytes(out)

# Fungsi untuk mengenkripsi data dan mengubahnya menjadi teks hex
def rc4_encrypt_hex(key, data):
    encrypted_data = rc4(key, data)
    return encrypted_data.hex()

# Fungsi untuk mendekripsi data dari teks hex menjadi data asli
def rc4_decrypt_hex(key, hex_data):
    encrypted_data = bytes.fromhex(hex_data)
    return rc4(key, encrypted_data)

# Inisialisasi antrian pesan dan dictionary klien
messages = queue.Queue()  # Antrian untuk pesan yang diterima
clients = {}  # Dictionary untuk menyimpan data client {addr: (username, password)}
user_data = {}  # Dictionary untuk menyimpan data pengguna yang terdaftar {username: password}
user_lock = threading.Lock()  # Lock untuk melindungi akses ke `user_data` dan `clients`

# Input untuk IP dan port server
server_ip = input("Enter server IP (e.g., localhost for all interfaces or specific IP): ")
server_port = int(input("Enter server port (e.g., 9999): "))

# Inisialisasi server UDP
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((server_ip, server_port))
server.settimeout(1)  # Timeout untuk mencegah blocking saat menerima pesan

print(f"Server is listening on {server_ip}:{server_port}...")

# Fungsi untuk memuat data pengguna dari file 'users.txt'
def load_user_data():
    if os.path.exists("users.txt"):
        with open("users.txt", "r") as f:
            for line in f.readlines():
                username, password = line.strip().split(":")
                user_data[username] = password

# Fungsi untuk menyimpan data pengguna ke file 'users.txt'
def save_user_data():
    with open("users.txt", "w") as f:
        for username, password in user_data.items():
            f.write(f"{username}:{password}\n")

# Fungsi untuk menerima pesan dari klien dan memasukkannya ke antrian
def receive():
    while True:
        try:
            message, addr = server.recvfrom(1024)  # Menerima pesan hingga 1024 byte
            messages.put((message, addr))  # Masukkan pesan ke dalam antrian
        except socket.timeout:
            continue  # Lewati jika tidak ada pesan yang diterima
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Fungsi untuk menyiarkan pesan ke semua klien
def broadcast():
    while True:
        if not messages.empty():
            # Ambil pesan berikutnya dari antrian
            encrypted_message, addr = messages.get()
            try:
                # Dekripsi pesan dari bentuk terenkripsi menjadi teks asli
                decrypted_message = rc4_decrypt_hex(SHARED_KEY, encrypted_message.decode()).decode()
            except Exception as e:
                print(f"Error decrypting message from client: {e}")
                continue

            # Menyimpan timestamp dari waktu saat ini
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

            # Jika klien baru bergabung
            if addr not in clients and decrypted_message.startswith("SIGNUP_TAG:"):
                try:
                    _, username, password = decrypted_message.split(":")
                    with user_lock:
                        # Periksa apakah username sudah ada di user_data
                        if username in user_data:
                            if user_data[username] == password:
                                # Jika username dan password cocok
                                if any(client_info[0] == username for client_info in clients.values()):
                                    server.sendto(rc4_encrypt_hex(SHARED_KEY, b"USERNAME_TAKEN").encode(), addr)
                                else:
                                    clients[addr] = (username, password)
                                    welcome_message = f"[{timestamp}] {username} rejoined the chat!"
                                    server.sendto(rc4_encrypt_hex(SHARED_KEY, b"LOGIN_SUCCESS").encode(), addr)
                                    for client in clients:
                                        if client != addr:
                                            server.sendto(rc4_encrypt_hex(SHARED_KEY, welcome_message.encode()).encode(), client)
                                    send_chat_history(addr)
                            else:
                                # Jika password tidak cocok
                                server.sendto(rc4_encrypt_hex(SHARED_KEY, b"WRONG_PASSWORD").encode(), addr)
                        else:
                            # Daftarkan username baru jika belum ada
                            if any(client_info[0] == username for client_info in clients.values()):
                                # Jika ada klien aktif dengan username ini, kirim "USERNAME_TAKEN"
                                server.sendto(rc4_encrypt_hex(SHARED_KEY, b"USERNAME_TAKEN").encode(), addr)
                                continue
                            user_data[username] = password
                            save_user_data()
                            clients[addr] = (username, password)
                            welcome_message = f"[{timestamp}] {username} joined the chat!"
                            server.sendto(rc4_encrypt_hex(SHARED_KEY, b"LOGIN_SUCCESS").encode(), addr)
                            for client in clients:
                                if client != addr:
                                    server.sendto(rc4_encrypt_hex(SHARED_KEY, welcome_message.encode()).encode(), client)
                            send_chat_history(addr)
                except ValueError:
                    error_message = "Signup failed. Invalid format."
                    server.sendto(rc4_encrypt_hex(SHARED_KEY, error_message.encode()).encode(), addr)
                continue

            # Jika klien keluar dari chat
            if decrypted_message == ":q":
                if addr in clients:
                    exit_message = f"[{timestamp}] {clients[addr][0]} has left the chat."
                    with user_lock:
                        clients.pop(addr)  # Hapus klien dari dictionary
                    for client in clients:
                        server.sendto(rc4_encrypt_hex(SHARED_KEY, exit_message.encode()).encode(), client)
                continue

            # Enkripsi pesan sebelum menyimpannya atau mengirimkannya
            if addr in clients:
                chat_message = f"[{timestamp}] {clients[addr][0]}: {decrypted_message}"
                encrypted_chat_message = rc4_encrypt_hex(SHARED_KEY, chat_message.encode())
                
                # Simpan pesan yang terenkripsi di file 'chat_history.txt'
                with open("chat_history.txt", "a") as f:
                    f.write(encrypted_chat_message + "\n")

                # Kirim pesan terenkripsi ke semua klien kecuali pengirim
                for client in clients:
                    if client != addr:
                        server.sendto(encrypted_chat_message.encode(), client)
        time.sleep(0.1)

# Fungsi untuk mengirim riwayat chat kepada klien yang sudah login
def send_chat_history(addr):
    if addr in clients:
        if os.path.exists("chat_history.txt"):
            with open("chat_history.txt", "r") as f:
                history = f.readlines()
                for line in history:
                    server.sendto(line.encode(), addr)

# Muat data pengguna saat server dimulai
load_user_data()

# Jalankan thread untuk menerima dan menyiarkan pesan
t1 = threading.Thread(target=receive)
t2 = threading.Thread(target=broadcast)

t1.start()
t2.start()
