import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from SimpleRSA import SimpleRSA
from rsa_key_manager import RSAKeyManager
from signer import Signer
from verifier import Verifier
import math, random, os

class RSASignatureApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ứng dụng chữ ký số RSA - SHA256")
        self.geometry("900x700")
        self.resizable(False, False) 
        
        self.simple_rsa = SimpleRSA() 
        self.private_key = None 
        self.public_key = None     
        self._last_signature = None  

        # tab thuc hien 
        self.tabs = ttk.Notebook(self)
        self.tab_gen = ttk.Frame(self.tabs)
        self.tab_sign = ttk.Frame(self.tabs)
        self.tab_verify = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_gen, text="Tạo khóa (RSA)")
        self.tabs.add(self.tab_sign, text="Ký tài liệu (RSA + SHA-256)")
        self.tabs.add(self.tab_verify, text="Xác minh chữ ký")
        self.tabs.pack(expand=1, fill="both")

        self.build_tab_generate()
        self.build_tab_sign()
        self.build_tab_verify()

    def build_tab_generate(self):
        frame = ttk.LabelFrame(self.tab_gen, text="Sinh khóa RSA", padding=10)
        frame.pack(fill="both", expand=True, padx=10, pady=10) # Sửa 'true'

        labels = [
            "p (số nguyên tố):", "q (số nguyên tố):",
            "n =", "φ(n) =", "e =", "d =", "Khóa công khai:", "Khóa bí mật:"
        ]
        self.gen_entries = {}
        for text in labels:
            ttk.Label(frame, text=text).pack(anchor="w", pady=2)
            entry = ttk.Entry(frame, width=95)
            entry.pack(pady=2)
            self.gen_entries[text] = entry

        btns = ttk.Frame(frame)
        btns.pack(pady=10)
        ttk.Button(btns, text="Ngẫu nhiên", command=self.random_primes).pack(side="left", padx=6)
        ttk.Button(btns, text="Tính toán", command=self.calculate_keys).pack(side="left", padx=6)
        ttk.Button(btns, text="Xóa", command=self.clear_gen_tab).pack(side="left", padx=6)

    def random_primes(self):
        try:
            # 1. Tạo và hiển thị khóa 
            self.simple_rsa.random_primes()
            self.show_rsa_info()
            
            # 2. Tự động tạo lưu khóa 
            self._generate_and_save_real_keys()
        except Exception as e: 
            messagebox.showerror("Lỗi", f"Tạo khóa ngẫu nhiên thất bại: {e}")

    def calculate_keys(self):
        try:
            # 1. Lấy p, q 
            p_text = self.gen_entries["p (số nguyên tố):"].get()
            q_text = self.gen_entries["q (số nguyên tố):"].get()
            
            if not p_text or not q_text:
                raise ValueError("Vui lòng nhập p và q")
                
            p = int(p_text)
            q = int(q_text)
            
            self.simple_rsa.p = p
            self.simple_rsa.q = q
            self.simple_rsa.calculate_keys()
            self.show_rsa_info()
            
            self._generate_and_save_real_keys()
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def show_rsa_info(self):
        info = self.simple_rsa.export_info()
        for k, v in zip(self.gen_entries.keys(), info.values()):
            self.gen_entries[k].delete(0, tk.END)
            self.gen_entries[k].insert(0, v)

    def clear_gen_tab(self):
        for entry in self.gen_entries.values():
            entry.delete(0, tk.END)

        self.simple_rsa = SimpleRSA() 

    def _generate_and_save_real_keys(self):
     
        try:
            # 1. Tạo khóa
            key = RSAKeyManager.generate_keypair(2048) 
            self.private_key = key
            self.public_key = key.publickey()

            # 2. Định nghĩa đường dẫn thư mục
            pub_path = "public_key.pem"
            priv_path = "private_key.pem"

            # 3. Lưu file
            RSAKeyManager.save_key_to_file(RSAKeyManager.export_public_key(self.public_key), pub_path) 
            RSAKeyManager.save_key_to_file(RSAKeyManager.export_private_key(self.private_key), priv_path) 
            
            # 4. Thông báo cho người dùng
            messagebox.showinfo("Tạo khóa thành công",
                                f"- {os.path.abspath(pub_path)}\n"
                                f"- {os.path.abspath(priv_path)}\n\n")
        except Exception as e: # Sửa 'exception'
            messagebox.showerror("Lỗi lưu khóa tự động", f"Không thể tạo hoặc lưu khóa .pem: {e}")


    #tao chu ky so
    def build_tab_sign(self):
        frame = ttk.LabelFrame(self.tab_sign, text="Ký tài liệu (RSA thật + SHA-256)", padding=10)
        frame.pack(fill="both", expand=True, padx=10, pady=10) # Sửa 'true'

        ttk.Label(frame, text="Dữ liệu cần ký:").grid(row=0, column=0, sticky="w")
        ttk.Button(frame, text="Tải file", command=self.load_file_to_sign).grid(row=0, column=1, sticky="w", padx=6)
        self.text_data = tk.Text(frame, width=105, height=14)
        self.text_data.grid(row=1, column=0, columnspan=4, pady=6)

        ttk.Button(frame, text="Tải khóa bí mật (.pem)", command=self.load_private_key_from_file).grid(row=2, column=0, sticky="w", pady=6)
        ttk.Button(frame, text="Ký tài liệu & Tự động lưu", command=self.sign_data).grid(row=2, column=1, sticky="w", pady=6)
        ttk.Button(frame, text="Xóa", command=self.clear_sign_tab).grid(row=2, column=2, sticky="w", pady=6)

        ttk.Label(frame, text="Băm (SHA-256):").grid(row=3, column=0, sticky="w", pady=(8,0))
        self.hash_entry = ttk.Entry(frame, width=100)
        self.hash_entry.grid(row=4, column=0, columnspan=4, pady=4)

        ttk.Label(frame, text="Chữ ký (HEX):").grid(row=5, column=0, sticky="w", pady=(8,0))
        self.signature_text = tk.Text(frame, width=105, height=6)
        self.signature_text.grid(row=6, column=0, columnspan=4, pady=6)

    def load_file_to_sign(self):
        path = filedialog.askopenfilename(title="Chọn file cần ký")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                txt = f.read()
            self.text_data.delete("1.0", tk.END)
            self.text_data.insert("1.0", txt)
            self._sign_file_path = None
        except Exception: 
            self.text_data.delete("1.0", tk.END)
            self.text_data.insert("1.0", f"[Binary file selected: {path}]")
            self._sign_file_path = path

    def load_private_key_from_file(self):
        file = filedialog.askopenfilename(title="Chọn khóa bí mật (.pem)", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if not file:
            return
        try:
            self.private_key = RSAKeyManager.load_key_from_file(file) 
            self.public_key = self.private_key.publickey()
            messagebox.showinfo("Thành công", "Đã tải khóa bí mật thành công! Khóa công khai cũng đã được cập nhật.")
        except Exception as e: 
            messagebox.showerror("Lỗi", f"Tải khóa thất bại: {e}")

    def sign_data(self):
        # 1. Chuẩn bị dữ liệu
        data = None
        if hasattr(self, "_sign_file_path") and self._sign_file_path:
            with open(self._sign_file_path, "rb") as f:
                data = f.read()
        else:
            text = self.text_data.get("1.0", tk.END).rstrip("\n")
            data = text.encode("utf-8")

        if not data:
            messagebox.showwarning("Thiếu dữ liệu", "Không có dữ liệu để ký.")
            return

        if not self.private_key:
            messagebox.showwarning("Chưa có khóa bí mật", "Bạn chưa tải khóa bí mật")
            return

        # 2. Ký dữ liệu
        signer = Signer(self.private_key) # 
        signature = signer.sign(data)
        self._last_signature = signature

        # 3. Hiển thị kết quả
        self.hash_entry.delete(0, tk.END)
        self.hash_entry.insert(0, signer.digest_hex(data))
        self.signature_text.delete("1.0", tk.END)
        self.signature_text.insert("1.0", signature.hex())
        
        # 4. Tự động lưu file
        try:
            # Xác định tên file gốc và lưu dữ liệu gốc
            data_filename = ""
            if hasattr(self, "_sign_file_path") and self._sign_file_path:
                # Lấy phần mở rộng của file gốc để lưu
                base_name = os.path.basename(self._sign_file_path)
                ext = os.path.splitext(base_name)[1]
                data_filename = f"signed_data{ext}" if ext else "signed_data.bin"
            else:
                data_filename = "signed_data.txt"
            
            # Lưu dữ liệu
            with open(data_filename, "wb") as f:
                f.write(data)

            # Lưu chữ ký
            sig_filename = "signature.sig"
            with open(sig_filename, "wb") as f:
                f.write(signature) 

            # 5. Thông báo thành công
            messagebox.showinfo("Ký số thành công",
                                f"Đã ký tài liệu thành công.\n\n"
                                f"Dữ liệu gốc đã lưu vào: {os.path.abspath(data_filename)}\n"
                                f"Chữ ký đã lưu vào: {os.path.abspath(sig_filename)}")

        except Exception as e:
            # Nếu ký thành công nhưng lưu file lỗi
            messagebox.showerror("Lỗi lưu file", f"Ký thành công, nhưng không thể tự động lưu file: {e}")

    def clear_sign_tab(self):
        self.text_data.delete("1.0", tk.END)
        self.hash_entry.delete(0, tk.END)
        self.signature_text.delete("1.0", tk.END)
        self._sign_file_path = None
        self._last_signature = None

# xác thực
    def build_tab_verify(self):
        frame = ttk.LabelFrame(self.tab_verify, text="Xác minh chữ ký", padding=10)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(frame, text="Dữ liệu cần xác minh:").grid(row=0, column=0, sticky="w")
        ttk.Button(frame, text="Tải file", command=self.load_verify_file).grid(row=0, column=1, sticky="w", padx=6)
        ttk.Button(frame, text="Tải chữ ký (.sig)", command=self.load_signature_from_file).grid(row=0, column=2, sticky="w", padx=6)
        self.text_verify = tk.Text(frame, width=105, height=14)
        self.text_verify.grid(row=1, column=0, columnspan=4, pady=6)

        ttk.Label(frame, text="Chữ ký (HEX):").grid(row=2, column=0, sticky="w", pady=(6,0))
        self.verify_sig_entry = ttk.Entry(frame, width=96)
        self.verify_sig_entry.grid(row=3, column=0, columnspan=3, pady=4, sticky="w")

        ttk.Button(frame, text="Tải khóa công khai (.pem)", command=self.load_public_key_from_file).grid(row=4, column=0, sticky="w", pady=6)
        ttk.Button(frame, text="Xác minh chữ ký", command=self.verify_signature).grid(row=4, column=1, sticky="w", pady=6)
        ttk.Button(frame, text="Xóa", command=self.clear_verify_tab).grid(row=4, column=2, sticky="w", pady=6)

        self.result_var = tk.StringVar(value="Chưa xác minh")
        ttk.Entry(frame, textvariable=self.result_var, state="readonly", width=96).grid(row=5, column=0, columnspan=4, pady=6)

    def load_verify_file(self):
        # Tải file dữ liệu gốc
        default_file = "signed_data.txt"
        if not os.path.exists(default_file):
            if os.path.exists("signed_data.bin"):
                default_file = "signed_data.bin"
        
        path = filedialog.askopenfilename(title="Chọn file để xác minh", initialfile=default_file if os.path.exists(default_file) else None)
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                txt = f.read()
            self.text_verify.delete("1.0", tk.END)
            self.text_verify.insert("1.0", txt)
            self._verify_file_path = None
        except Exception:
            self.text_verify.delete("1.0", tk.END)
            self.text_verify.insert("1.0", f"[Binary file selected: {path}]")
            self._verify_file_path = path

    def load_signature_from_file(self):
        # Tải file chữ ký
        default_file = "signature.sig"
        path = filedialog.askopenfilename(title="Chọn file chữ ký (.sig)", initialfile=default_file if os.path.exists(default_file) else None, filetypes=[("Signature files", "*.sig"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                sig = f.read()

            self.verify_sig_entry.delete(0, tk.END)
            self.verify_sig_entry.insert(0, sig.hex())
            self._loaded_signature_bytes = sig
            messagebox.showinfo("Tải chữ ký", "Đã tải chữ ký từ file.")
        except Exception as e: 
            messagebox.showerror("Lỗi", f"Tải chữ ký thất bại: {e}")

    def load_public_key_from_file(self):
        # Tải file khóa
        default_file = "public_key.pem"
        file = filedialog.askopenfilename(title="Chọn khóa công khai (.pem)", initialfile=default_file if os.path.exists(default_file) else None, filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if not file:
            return
        try:
            self.public_key = RSAKeyManager.load_key_from_file(file) 
            messagebox.showinfo("Thành công", "Đã tải khóa công khai thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Tải khóa thất bại: {e}")

    def verify_signature(self):
        # 1. Chuẩn bị dữ liệu
        data = None
        if hasattr(self, "_verify_file_path") and self._verify_file_path:
            with open(self._verify_file_path, "rb") as f:
                data = f.read()
        else:
            text = self.text_verify.get("1.0", tk.END).rstrip("\n")
            data = text.encode("utf-8")

        if not data:
            messagebox.showwarning("Thiếu dữ liệu", "Bạn chưa cung cấp dữ liệu để xác minh.")
            return

        # 2. Chuẩn bị chữ ký
        sig_bytes = None 
        if hasattr(self, "_loaded_signature_bytes") and self._loaded_signature_bytes:
            sig_bytes = self._loaded_signature_bytes
            self._loaded_signature_bytes = None
        else:
            hex_text = self.verify_sig_entry.get().strip()
            if not hex_text:
                messagebox.showwarning("Thiếu chữ ký", "Bạn chưa cung cấp chữ ký để xác minh.")
                return
            try:
                sig_bytes = bytes.fromhex(hex_text)
            except Exception:
                messagebox.showerror("Lỗi", "Chữ ký không hợp lệ.")
                return

        if not self.public_key:
            messagebox.showwarning("Thiếu khóa", "Bạn chưa tải khóa công khai.")
            return

        # 3. Xác minh
        verifier = Verifier(self.public_key)
        try:
            ok = verifier.verify(data, sig_bytes)
            self.result_var.set("Hợp lệ" if ok else "Không hợp lệ")
            if ok:
                messagebox.showinfo("Kết quả", "Chữ ký hợp lệ.")
            else:
                messagebox.showwarning("Kết quả", "Chữ ký KHÔNG hợp lệ.")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Xác minh thất bại: {e}")

    def clear_verify_tab(self):
        self.text_verify.delete("1.0", tk.END)
        self.verify_sig_entry.delete(0, tk.END)
        self.result_var.set("Chưa xác minh")
        self._loaded_signature_bytes = None 
        self._verify_file_path = None
