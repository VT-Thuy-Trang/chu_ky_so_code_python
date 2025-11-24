import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from SimpleRSA import SimpleRSA
from rsa_key_manager import RSAKeyManager
from signer import Signer
from verifier import Verifier
import os

# lớp chính của ứng dụng GUI
class RSASignatureApp(tk.Tk):
    # khởi tạo giao diện chính
    def __init__(self):
        super().__init__()
        self.title("Ứng dụng chữ ký số RSA - SHA256")
        self.geometry("1100x750") 
        self.resizable(False, False) 
        
        # thiết lập Cấu hình 
        style = ttk.Style()
        style.configure("Header.TLabel", font=("Arial", 24, "bold"), foreground="#4a7abc")
        style.configure("SubHeader.TLabel", font=("Arial", 12, "bold"), foreground="#4a7abc")
        style.configure("TLabel", font=("Arial", 11))
        style.configure("TButton", font=("Arial", 10))
        
        # tạo các biến cần thiết
        self.simple_rsa = SimpleRSA() 
        self.private_key = None 
        self.public_key = None     
        self._sign_file_path = None
        self._verify_file_path = None
        self._loaded_signature_bytes = None

        # tạo tab thực hiện ký số
        self.tabs = ttk.Notebook(self)
        self.tab_gen = ttk.Frame(self.tabs)
        self.tab_main = ttk.Frame(self.tabs) 
        
        self.tabs.add(self.tab_gen, text="1. Tạo cặp khóa")
        self.tabs.add(self.tab_main, text="2. Mã hóa / Ký & Xác minh")
        self.tabs.pack(expand=1, fill="both")

        self.build_tab_generate()
        self.build_tab_main()


    # trang tạo cặp khóa (khóa công khai và khóa bí mật)

    def build_tab_generate(self):
        # Frame giữa
        wrapper = ttk.Frame(self.tab_gen)
        wrapper.pack(expand=True, fill="both", padx=100, pady=20)
        
        # Tiêu đề
        lbl_title = ttk.Label(wrapper, text="Tạo cặp khóa", style="Header.TLabel")
        lbl_title.pack(pady=(0, 30))

        # content frame
        content = ttk.Frame(wrapper)
        content.pack(fill="x")
        content.columnconfigure(1, weight=1)

        self.gen_entries = {}

        # tạo hàm nhập liệu
        def add_row(parent, label, key, row, readonly=False):
            ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=10)
            entry = ttk.Entry(parent, font=("Arial", 11))
            entry.grid(row=row, column=1, sticky="ew", pady=10, padx=(10, 0))
            if readonly: entry.state(["readonly"])
            self.gen_entries[key] = entry
            return row + 1

        r = 0
        r = add_row(content, "Số nguyên tố bí mật p =", "p", r)
        r = add_row(content, "Số nguyên tố bí mật q =", "q", r)

        # các nút xác nhận
        btn_frame = ttk.Frame(content)
        btn_frame.grid(row=r, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Ngẫu nhiên", command=self.random_primes, width=15).pack(side="left", padx=20)
        ttk.Button(btn_frame, text="Tính toán", command=self.calculate_keys, width=15).pack(side="left", padx=20)
        
        r += 1

        # Các trường kết quả
        r = add_row(content, "Modulus n =", "n", r)
        r = add_row(content, "Hàm số Ơle Φ(n) =", "phi_n", r)
        r = add_row(content, "Số mũ công khai e =", "e", r)
        r = add_row(content, "Số mũ bí mật d =", "d", r)
        r = add_row(content, "Khóa public (n, e) =", "public_key", r)
        r = add_row(content, "Khóa private (n, d) =", "private_key", r)
    
    # chọn ngẫu nhiên p, q
    def random_primes(self):
        try:
            self.simple_rsa.random_primes()
            self.show_rsa_info()
            self._generate_and_save_real_keys()
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    # tính toán các khóa
    def calculate_keys(self):
        try:
            p = int(self.gen_entries["p"].get())
            q = int(self.gen_entries["q"].get())
            self.simple_rsa.p = p
            self.simple_rsa.q = q
            self.simple_rsa.calculate_keys()
            self.show_rsa_info()
            self._generate_and_save_real_keys()
        except Exception as e:
            messagebox.showerror("Lỗi", f"Dữ liệu nhập không hợp lệ: {e}")

    # hiển thị thông tin RSA
    def show_rsa_info(self):
        info = self.simple_rsa.export_info()
        for k, v in info.items():
            if k in self.gen_entries:
                self.gen_entries[k].delete(0, tk.END)
                self.gen_entries[k].insert(0, str(v))

    # tạo và lưu khóa sử dụng
    def _generate_and_save_real_keys(self):
        try:
            # Tạo khóa thật để dùng cho Signing/Verifying
            key = RSAKeyManager.generate_keypair(2048)
            self.private_key = key
            self.public_key = key.publickey()
            RSAKeyManager.save_key_to_file(RSAKeyManager.export_public_key(self.public_key), "public_key.pem")
            RSAKeyManager.save_key_to_file(RSAKeyManager.export_private_key(self.private_key), "private_key.pem")
            messagebox.showinfo("Thông báo", "Đã tạo và lưu khóa thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể lưu khóa: {e}")



    #MÃ HÓA / KÝ & XÁC MINH

    def build_tab_main(self):
        wrapper = ttk.Frame(self.tab_main)
        wrapper.pack(expand=True, fill="both", padx=20, pady=10)

        #cặp khóa
        top_frame = ttk.Frame(wrapper)
        top_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(top_frame, text="Tạo cặp khóa : ", font=("Arial", 12, "bold"), foreground="#4a7abc").pack(side="left")
        ttk.Button(top_frame, text="Sinh khóa ngẫu nhiên", command=self.random_primes).pack(side="left", padx=5)

        # Mã hóa
        ttk.Label(wrapper, text="Mã hóa", style="Header.TLabel").pack(pady=(0, 20))

 
        paned = ttk.PanedWindow(wrapper, orient="horizontal")
        paned.pack(expand=True, fill="both")


        left_frame = ttk.Frame(paned, padding=(0, 0, 20, 0))
        paned.add(left_frame, weight=1)

        #Dữ liệu gốc [Tải file] [Ký số]
        row1_l = ttk.Frame(left_frame)
        row1_l.pack(fill="x", pady=5)
        ttk.Label(row1_l, text="Dữ liệu gốc", font=("Arial", 11, "bold")).pack(side="left")
        ttk.Button(row1_l, text="Ký số", command=self.sign_data).pack(side="right", padx=2)
        ttk.Button(row1_l, text="Tải file", command=self.load_file_sign).pack(side="right", padx=2)

        
        self.txt_data_sign = tk.Text(left_frame, height=5, borderwidth=1, relief="solid")
        self.txt_data_sign.pack(fill="x", pady=5)
        self.txt_data_sign.insert("1.0", "Demo chữ ký số")

        # Kết quả băm
        ttk.Label(left_frame, text="Kết quả băm (SHA-256)", font=("Arial", 11, "bold")).pack(anchor="w", pady=(15, 5))
        self.ent_hash_sign = ttk.Entry(left_frame)
        self.ent_hash_sign.pack(fill="x")

        # Chữ ký số
        ttk.Label(left_frame, text="Chữ ký số", font=("Arial", 11, "bold")).pack(anchor="w", pady=(15, 5))
        self.txt_sig_sign = tk.Text(left_frame, height=5, borderwidth=1, relief="solid") 
        self.txt_sig_sign.pack(fill="x", pady=5)
        
        ttk.Button(left_frame, text="Sao chép chữ ký", command=self.copy_signature).pack(anchor="w", pady=5)


        
        right_frame = ttk.Frame(paned, padding=(20, 0, 0, 0))
        paned.add(right_frame, weight=1)

        #Dữ liệu cần xác minh [Tải file] [Băm]
        row1_r = ttk.Frame(right_frame)
        row1_r.pack(fill="x", pady=5)
        ttk.Label(row1_r, text="Dữ liệu cần xác minh", font=("Arial", 11, "bold")).pack(side="left")
        ttk.Button(row1_r, text="Băm", command=self.calc_hash_verify).pack(side="right", padx=2)
        ttk.Button(row1_r, text="Tải file", command=self.load_file_verify).pack(side="right", padx=2)

        
        self.txt_data_verify = tk.Text(right_frame, height=5, borderwidth=1, relief="solid")
        self.txt_data_verify.pack(fill="x", pady=5)
        self.txt_data_verify.insert("1.0", "Demo chữ ký số")

        # Kết quả băm
        ttk.Label(right_frame, text="Kết quả băm (SHA-256)", font=("Arial", 11, "bold")).pack(anchor="w", pady=(15, 5))
        self.ent_hash_verify = ttk.Entry(right_frame)
        self.ent_hash_verify.pack(fill="x")

        # Chữ ký số [Giải mã]
        ttk.Label(right_frame, text="Chữ ký số", font=("Arial", 11, "bold")).pack(anchor="w", pady=(15, 5))
        row_sig_v = ttk.Frame(right_frame)
        row_sig_v.pack(fill="x")
        self.ent_sig_verify = ttk.Entry(row_sig_v) 
        self.ent_sig_verify.pack(side="left", fill="x", expand=True)
        ttk.Button(row_sig_v, text="Giải mã", command=self.decrypt_signature_visual).pack(side="left", padx=(5, 0))

        # Giải mã chữ ký số
        ttk.Label(right_frame, text="Giải mã chữ ký số", font=("Arial", 11, "bold")).pack(anchor="w", pady=(15, 5))
        row_dec_v = ttk.Frame(right_frame)
        row_dec_v.pack(fill="x")
        self.ent_decrypted_verify = ttk.Entry(row_dec_v)
        self.ent_decrypted_verify.pack(side="left", fill="x", expand=True)
        ttk.Button(row_dec_v, text="Xác minh", command=self.verify_final).pack(side="left", padx=(5, 0))

        
        ttk.Button(wrapper, text="Làm mới", command=self.clear_main_tab, width=15).pack(side="bottom", pady=20)


    
    # logic ký số
    def load_file_sign(self):
        path = filedialog.askopenfilename(title="Chọn file cần ký")
        if path:
            self._sign_file_path = path
            self.txt_data_sign.delete("1.0", tk.END)
            self.txt_data_sign.insert("1.0", f"[File]: {os.path.basename(path)}")
            # Auto hash
            with open(path, "rb") as f: data = f.read()
            self.ent_hash_sign.delete(0, tk.END)
            self.ent_hash_sign.insert(0, Signer.digest_hex(data))
    
    # ký số
    def sign_data(self):
        # tự động load khóa nếu chưa có
        if not self.private_key:
            if os.path.exists("private_key.pem"):
                self.private_key = RSAKeyManager.load_key_from_file("private_key.pem")
            else:
                messagebox.showwarning("Thiếu khóa", "Vui lòng tạo khóa ở Tab 1 trước.")
                return

        # dữ liệu cần ký
        data = None
        if self._sign_file_path:
            with open(self._sign_file_path, "rb") as f: data = f.read()
        else:
            data = self.txt_data_sign.get("1.0", tk.END).strip().encode("utf-8")

        # ký
        try:
            signer = Signer(self.private_key)
            sig = signer.sign(data)
            
            # Display Hash & Sig
            self.ent_hash_sign.delete(0, tk.END)
            self.ent_hash_sign.insert(0, signer.digest_hex(data))
            
            self.txt_sig_sign.delete("1.0", tk.END)
            self.txt_sig_sign.insert("1.0", sig.hex())
            
            # tự động lưu file chữ ký
            with open("signature.sig", "wb") as f: f.write(sig)
            messagebox.showinfo("Thành công", "Đã ký và lưu file 'signature.sig'")
            
            # Tự động điền sang bên test
            self.ent_sig_verify.delete(0, tk.END)
            self.ent_sig_verify.insert(0, sig.hex())
            
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    # sao chép chữ ký
    def copy_signature(self):
        self.clipboard_clear()
        self.clipboard_append(self.txt_sig_sign.get("1.0", tk.END).strip())
        messagebox.showinfo("Copy", "Đã sao chép chữ ký!")

   
    # logic xác minh chữ ký
    def load_file_verify(self):
        path = filedialog.askopenfilename(title="Chọn file xác minh")
        if path:
            self._verify_file_path = path
            self.txt_data_verify.delete("1.0", tk.END)
            self.txt_data_verify.insert("1.0", f"[File]: {os.path.basename(path)}")
            self.calc_hash_verify()

    # tính toán băm
    def calc_hash_verify(self):
        # lấy dữ liệu
        try:
            data = None
            if self._verify_file_path:
                with open(self._verify_file_path, "rb") as f: data = f.read()
            else:
                data = self.txt_data_verify.get("1.0", tk.END).strip().encode("utf-8")
            # tính băm
            h = Signer.digest_hex(data)
            self.ent_hash_verify.delete(0, tk.END)
            self.ent_hash_verify.insert(0, h)
            return data # trả về dữ liệu để dùng xác minh
        except: return None
    
    # giải mã chữ ký số để hiển thị
    def decrypt_signature_visual(self):
        # Lấy khóa
        if not self.public_key:
             if os.path.exists("public_key.pem"):
                self.public_key = RSAKeyManager.load_key_from_file("public_key.pem")
             else:
                 messagebox.showwarning("Lỗi", "Chưa có khóa công khai")
                 return
        # Lấy chữ ký
        hex_sig = self.ent_sig_verify.get().strip()
        if not hex_sig: return

        try:
            # Chuyển chữ ký hex -> số nguyên
            sig_int = int(hex_sig, 16)
            
            # Thực hiện phép tính RSA thô: m = s^e mod n
            # (Lấy e, n từ khóa công khai)
            e = self.public_key.e
            n = self.public_key.n
            decrypted_int = pow(sig_int, e, n)
            
            # Chuyển lại thành Hex để hiển thị
            decrypted_hex = hex(decrypted_int)[2:]
            
            self.ent_decrypted_verify.delete(0, tk.END)
            self.ent_decrypted_verify.insert(0, decrypted_hex)
            
        except Exception as e:
            messagebox.showerror("Lỗi giải mã", str(e))

    def verify_final(self):
        # 1. Lấy khóa
        if not self.public_key:
             if os.path.exists("public_key.pem"):
                self.public_key = RSAKeyManager.load_key_from_file("public_key.pem")
             else:
                 messagebox.showwarning("Lỗi", "Thiếu khóa công khai")
                 return

        # 2. Lấy Data & Hash
        data = self.calc_hash_verify() # Đảm bảo hash entry được cập nhật
        if data is None: return

        # 3. Lấy Chữ ký
        hex_sig = self.ent_sig_verify.get().strip()
        try:
            sig_bytes = bytes.fromhex(hex_sig)
        except:
            messagebox.showerror("Lỗi", "Chữ ký Hex không hợp lệ")
            return

        # 4. Xác minh chuẩn (PKCS#1 v1.5)
        verifier = Verifier(self.public_key)
        is_valid = verifier.verify(data, sig_bytes)

        if is_valid:
            messagebox.showinfo("Kết quả", "Xác minh THÀNH CÔNG!\nChữ ký khớp với dữ liệu.")
        else:
            messagebox.showerror("Kết quả", "Xác minh THẤT BẠI!\nChữ ký không khớp hoặc dữ liệu bị thay đổi.")

    # làm mới tab chính
    def clear_main_tab(self):
        self.txt_data_sign.delete("1.0", tk.END)
        self.ent_hash_sign.delete(0, tk.END)
        self.txt_sig_sign.delete("1.0", tk.END)
        
        self.txt_data_verify.delete("1.0", tk.END)
        self.ent_hash_verify.delete(0, tk.END)
        self.ent_sig_verify.delete(0, tk.END)
        self.ent_decrypted_verify.delete(0, tk.END)
        
        self._sign_file_path = None
        self._verify_file_path = None