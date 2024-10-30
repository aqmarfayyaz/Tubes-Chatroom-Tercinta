import socket  # Untuk komunikasi jaringan
import threading  # Untuk menjalankan beberapa proses bersamaan (multithreading)
import random  # Untuk memilih port secara acak
import tkinter as tk  # Untuk GUI (antarmuka pengguna)
from tkinter import scrolledtext, simpledialog, messagebox, colorchooser
from tkinter import PhotoImage, Frame, Label
import datetime  # Untuk mendapatkan waktu dan tanggal

# Kunci enkripsi yang digunakan oleh client dan server untuk RC4
SHARED_KEY = b'my_shared_rc4_key'

# Fungsi RC4 untuk enkripsi dan dekripsi data menggunakan kunci
def rc4(key, data):
    S = list(range(256))  # Inisialisasi array S dengan angka 0 hingga 255
    j = 0
    out = []

    # Permutasi kunci RC4 (Key-Scheduling Algorithm)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    # Proses enkripsi menggunakan RC4 (Pseudo-Random Generation Algorithm)
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    return bytes(out)

# Fungsi untuk mengenkripsi data dan mengubahnya ke dalam teks hexadecimal
def rc4_encrypt_hex(key, data):
    encrypted_data = rc4(key, data)
    return encrypted_data.hex()

# Fungsi untuk mendekripsi data dari teks hex menjadi data asli
def rc4_decrypt_hex(key, hex_data):
    encrypted_data = bytes.fromhex(hex_data)
    return rc4(key, encrypted_data)

# Kelas utama untuk client chat
class ChatClient:
    def __init__(self, master):
        # Inisialisasi jendela utama (root)
        self.master = master
        self.master.title("Chatroom MahasiswaShooters")
        self.master.geometry("500x700")
        self.master.configure(bg="#222222")  # Background gelap untuk mode malam

        # Header dengan ikon profil dan status
        self.header_frame = Frame(self.master, bg="#333333", height=50)
        self.header_frame.pack(fill=tk.X)
        
        # Ikon profil pengguna
        self.profile_image = PhotoImage(file="src/profile_icon.png")
        self.profile_label = Label(self.header_frame, image=self.profile_image, bg="#333333")
        self.profile_label.pack(side=tk.LEFT, padx=10)

        # Label status "Online"
        self.status_label = Label(self.header_frame, text="Online", fg="white", bg="#333333", font=("Helvetica", 14))
        self.status_label.pack(side=tk.LEFT, padx=5)

        # Tombol untuk mengganti mode gelap/terang
        self.dark_mode = True
        self.switch_mode_button = tk.Button(self.header_frame, text="Switch Mode", bg="#444444", fg="white", font=("Helvetica", 10),
                                            command=self.toggle_mode)
        self.switch_mode_button.pack(side=tk.RIGHT, padx=10)

        # Tombol untuk memilih warna tema
        self.color_button = tk.Button(self.header_frame, text="Choose Color", bg="#444444", fg="white", font=("Helvetica", 10),
                                      command=self.choose_color)
        self.color_button.pack(side=tk.RIGHT, padx=10)

        # Area untuk menampilkan pesan (dengan scroll)
        self.chat_area = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, state='disabled', bg="#2b2b2b", fg="white", font=("Helvetica", 12), bd=0, padx=10, pady=10)
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Area input untuk mengetik pesan
        self.input_area = tk.Text(self.master, height=3, font=("Helvetica", 12), bg="#444444", fg="white", bd=1, relief=tk.FLAT, wrap=tk.WORD, padx=10, pady=10)
        self.input_area.pack(padx=10, pady=(0, 10), fill=tk.X, side=tk.BOTTOM)

        # Tombol kirim dengan efek hover
        self.send_button = tk.Button(self.master, text="Send", command=self.send_message, bg="#25D366", fg="white", font=("Helvetica", 12),
                                     relief=tk.FLAT)
        self.send_button.pack(pady=4, side=tk.RIGHT, padx=10)
        self.send_button.bind("<Enter>", self.on_button_hover)
        self.send_button.bind("<Leave>", self.on_button_leave)

        # Menambahkan bind untuk tombol Enter sebagai alternatif tombol kirim
        self.master.bind("<Return>", lambda event: self.send_message())

        # Meminta IP dan port server dari pengguna
        self.server_ip = simpledialog.askstring("Server IP", "Enter server IP (e.g., localhost or IP address):", parent=self.master)
        self.server_port = int(simpledialog.askstring("Server Port", "Enter server port (e.g., 9999):", parent=self.master))

        # Membuat socket untuk komunikasi UDP
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.bind(("0.0.0.0", random.randint(8000, 9000)))  # Bind dengan port acak di client
        self.client.settimeout(1)  # Timeout untuk penerimaan pesan

        # Meminta username dari pengguna
        self.username = simpledialog.askstring("Username", "Enter your username:", parent=self.master)
        self.register_user()  # Mendaftarkan pengguna ke server

        # Membuat thread untuk menerima pesan agar tidak mengganggu antarmuka
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True  # Agar thread berhenti saat program dihentikan
        self.receive_thread.start()

    # Fungsi untuk mengirim pesan ke server
    def send_message(self):
        message = self.input_area.get("1.0", tk.END).strip()  # Mengambil teks dari area input
        if message == "":
            messagebox.showwarning("Warning", "You can't send an empty message!")
            return

        # Jika pesan adalah ":q", keluar dari chat
        if message == ":q":
            encrypted_message = rc4_encrypt_hex(SHARED_KEY, ":q".encode())
            self.client.sendto(encrypted_message.encode(), (self.server_ip, self.server_port))
            self.master.quit()  # Menutup jendela utama
            return

        # Enkripsi pesan dan kirimkan ke server
        encrypted_message = rc4_encrypt_hex(SHARED_KEY, message.encode())
        self.client.sendto(encrypted_message.encode(), (self.server_ip, self.server_port))
        self.append_message(f"You: {message}", from_self=True)  # Menampilkan pesan di area chat
        self.input_area.delete("1.0", tk.END)  # Hapus teks di area input setelah dikirim

    # Fungsi untuk menerima pesan dari server
    def receive_messages(self):
        while True:
            try:
                # Menerima pesan yang dienkripsi dari server
                encrypted_message, _ = self.client.recvfrom(1024)
                message = rc4_decrypt_hex(SHARED_KEY, encrypted_message.decode()).decode()  # Dekripsi pesan
                self.append_message(message)  # Tampilkan pesan di area chat
            except socket.timeout:
                continue  # Lewati jika timeout
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    # Fungsi untuk menampilkan pesan di area chat
    def append_message(self, message, from_self=False):
        timestamp = datetime.datetime.now().strftime("%H:%M")  # Mendapatkan waktu saat ini
        self.chat_area.config(state=tk.NORMAL)
        if from_self:
            # Pesan dari diri sendiri ditampilkan dengan gaya khusus
            self.chat_area.insert(tk.END, f"[{timestamp}] {message}\n\n", "sent")
        else:
            self.chat_area.insert(tk.END, f"[{timestamp}] {message}\n\n", "received")
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.yview(tk.END)  # Scroll ke bawah otomatis saat ada pesan baru

        # Pengaturan warna balon chat
        self.chat_area.tag_config("sent", foreground="#25D366", font=("Helvetica", 12, "bold"))  
        self.chat_area.tag_config("received", foreground="#FFFFFF", font=("Helvetica", 12))  

    # Fungsi untuk beralih antara mode gelap dan terang
    def toggle_mode(self):
        if self.dark_mode:
            # Beralih ke mode terang
            self.master.configure(bg="#ffffff")
            self.chat_area.configure(bg="#f0f0f0", fg="black")
            self.input_area.configure(bg="#e5e5e5", fg="black")
            self.switch_mode_button.configure(bg="#cccccc", fg="black")
            self.color_button.configure(bg="#cccccc", fg="black")
            self.header_frame.configure(bg="#cccccc")
            self.status_label.configure(bg="#cccccc", fg="black")
            self.profile_label.configure(bg="#cccccc")
            self.send_button.configure(bg="#cccccc", fg="black") 
            self.chat_area.tag_config("sent", foreground="green", font=("Helvetica", 12, "bold"))
            self.chat_area.tag_config("received", foreground="black", font=("Helvetica", 12))
            self.dark_mode = False
        else:
            # Beralih ke mode gelap
            self.master.configure(bg="#222222")
            self.chat_area.configure(bg="#2b2b2b", fg="white")
            self.input_area.configure(bg="#444444", fg="white")
            self.switch_mode_button.configure(bg="#444444", fg="white")
            self.color_button.configure(bg="#444444", fg="white")
            self.header_frame.configure(bg="#333333")
            self.status_label.configure(bg="#333333", fg="white")
            self.profile_label.configure(bg="#333333")
            self.send_button.configure(bg="#25D366", fg="white")
            self.chat_area.tag_config("sent", foreground="#25D366", font=("Helvetica", 12, "bold"))
            self.chat_area.tag_config("received", foreground="white", font=("Helvetica", 12))
            self.dark_mode = True


    # Fungsi untuk memilih warna tema
    def choose_color(self):
        color = colorchooser.askcolor(title="Choose a color")
        if color[1]:  # Jika pengguna memilih warna
            self.master.configure(bg=color[1])
            self.chat_area.configure(bg=color[1])

            # Deteksi apakah warna terang atau gelap
            r, g, b = self.master.winfo_rgb(color[1])
            brightness = (r + g + b) / 3

            if brightness > (65535 / 2):  # Ambang batas untuk warna terang
                text_color = "black"
            else:
                text_color = "white"

            # Setel warna teks berdasarkan warna latar belakang
            self.chat_area.configure(fg=text_color)
            self.input_area.configure(fg=text_color)
            self.switch_mode_button.configure(fg=text_color)
            self.color_button.configure(fg=text_color)
            self.status_label.configure(fg=text_color)
            self.send_button.configure(fg=text_color)
            self.chat_area.tag_config("sent", foreground="green" if text_color == "black" else "#25D366", font=("Helvetica", 12, "bold"))
            self.chat_area.tag_config("received", foreground=text_color, font=("Helvetica", 12))


    # Fungsi untuk mendaftarkan pengguna ke server dengan username dan password
    # Fungsi untuk mendaftarkan pengguna ke server dengan username dan password
    def register_user(self):
        password = simpledialog.askstring("Password", "Enter your password:", parent=self.master, show='*')
        credentials = f"SIGNUP_TAG:{self.username}:{password}"

        # Enkripsi data registrasi dan kirimkan ke server
        encrypted_credentials = rc4_encrypt_hex(SHARED_KEY, credentials.encode())
        self.client.sendto(encrypted_credentials.encode(), (self.server_ip, self.server_port))

        try:
            # Menunggu respons dari server
            response, _ = self.client.recvfrom(1024)
            response = rc4_decrypt_hex(SHARED_KEY, response.decode()).decode()
            
            if response == "LOGIN_SUCCESS":
                self.append_message(f"[INFO] You have joined the chat as {self.username}!", from_self=True)
            elif response == "WRONG_PASSWORD":
                messagebox.showerror("Login Error", "Incorrect password. Please try again.")
                self.username = simpledialog.askstring("Username", "Enter your username:", parent=self.master)
                self.register_user()
            elif response == "USERNAME_TAKEN":
                messagebox.showerror("Username Error", "Username already taken, try another one.")
                self.username = simpledialog.askstring("Username", "Enter your username:", parent=self.master)
                self.register_user()
            else:
                messagebox.showerror("Unknown Error", "An unknown error occurred.")
        except socket.timeout:
            messagebox.showerror("Server Timeout", "No response from server.")


    # Efek hover pada tombol kirim
    def on_button_hover(self, event):
        event.widget.config(bg="#4CAF50") 

    def on_button_leave(self, event):
        event.widget.config(bg="#5cb85c")  # Warna kembali ke warna awal

# Jalankan aplikasi utama
if __name__ == "__main__":
    root = tk.Tk()
    client_app = ChatClient(root)
    root.mainloop()
