# import tkinter as tk
# from tkinter import ttk, filedialog, messagebox
# from crypto.publickey import rsa
# from crypto.signature import pkcs1_15
# from crypto.hash import sha256
# import math, random, os


# # thuật toán rsa cơ bản

# class simplersa:
#     def __init__(self):
#         self.p = none
#         self.q = none
#         self.n = none
#         self.phi_n = none
#         self.e = none
#         self.d = none

#     def is_prime(self, num):
#         if num is none: return false
#         if num < 2: return false
#         for i in range(2, int(math.sqrt(num)) + 1):
#             if num % i == 0:
#                 return false
#         return true

#     def random_primes(self):
#         primes = [i for i in range(100, 500) if self.is_prime(i)]
#         self.p, self.q = random.sample(primes, 2)
#         self.calculate_keys()

#     def calculate_keys(self):
#         if not self.p or not self.q:
#             raise valueerror("chưa có p, q")
#         if not self.is_prime(self.p) or not self.is_prime(self.q):
#             raise valueerror("p hoặc q không phải số nguyên tố")
#         if self.p == self.q:
#             raise valueerror("p và q không được bằng nhau")

#         self.n = self.p * self.q
#         self.phi_n = (self.p - 1) * (self.q - 1)
#         # chọn e đơn giản: thử các số nhỏ; trong thực tế dùng 65537
#         try:
#             self.e = next(e for e in (3,5,17,257,65537) if e < self.phi_n and math.gcd(e, self.phi_n) == 1)
#         except stopiteration:
#             self.e = next(e for e in range(3, self.phi_n) if math.gcd(e, self.phi_n) == 1)
#         self.d = pow(self.e, -1, self.phi_n)

#     def export_info(self):
#         return {
#             "p": self.p,
#             "q": self.q,
#             "n": self.n,
#             "phi_n": self.phi_n,
#             "e": self.e,
#             "d": self.d,
#             "public_key": f"({self.n}, {self.e})",
#             "private_key": f"({self.n}, {self.d})"
#         }


# # class 2: quản lý khóa rsa 
# class rsakeymanager:

#     def generate_keypair(bits=2048):
#         return rsa.generate(bits)


#     def export_private_key(key):
#         return key.export_key()


#     def export_public_key(key):
#         return key.publickey().export_key()


#     def save_key_to_file(key_data, filename):
#         with open(filename, "wb") as f:
#             f.write(key_data)


#     def load_key_from_file(filename):
#         with open(filename, "rb") as f:
#             data = f.read()
#         return rsa.import_key(data)


# #ký và xác minh chữ ký

# class signer:
#     def __init__(self, private_key):
#         self.private_key = private_key

#     def sign(self, data: bytes):
#         h = sha256.new(data)
#         return pkcs1_15.new(self.private_key).sign(h)

#     @staticmethod
#     def digest_hex(data: bytes):
#         return sha256.new(data).hexdigest()

# class verifier:
#     def __init__(self, public_key):
#         self.public_key = public_key

#     def verify(self, data: bytes, signature: bytes):
#         h = sha256.new(data)
#         try:
#             pkcs1_15.new(self.public_key).verify(h, signature)
#             return true
#         except (valueerror, typeerror):
#             return false


# # giao diện chính
# class rsasignatureapp(tk.tk):
#     def __init__(self):
#         super().__init__()
#         self.title("ứng dụng chữ ký số rsa - sha256")
#         self.geometry("900x700")
#         self.resizable(false, false)
#         self.simple_rsa = simplersa()
#         self.private_key = none   
#         self.public_key = none     
#         self._last_signature = none  

#         # tabs
#         self.tabs = ttk.notebook(self)
#         self.tab_gen = ttk.frame(self.tabs)
#         self.tab_sign = ttk.frame(self.tabs)
#         self.tab_verify = ttk.frame(self.tabs)
#         self.tabs.add(self.tab_gen, text="tạo khóa (rsa mô phỏng)")
#         self.tabs.add(self.tab_sign, text="ký tài liệu (rsa + sha-256)")
#         self.tabs.add(self.tab_verify, text="xác minh chữ ký")
#         self.tabs.pack(expand=1, fill="both")

#         self.build_tab_generate()
#         self.build_tab_sign()
#         self.build_tab_verify()

#     #tao khoa
#     def build_tab_generate(self):
#         frame = ttk.labelframe(self.tab_gen, text="sinh khóa rsa (mô phỏng)", padding=10)
#         frame.pack(fill="both", expand=true, padx=10, pady=10)

#         labels = [
#             "p (số nguyên tố):", "q (số nguyên tố):",
#             "n =", "φ(n) =", "e =", "d =", "khóa công khai:", "khóa bí mật:"
#         ]
#         self.gen_entries = {}
#         for text in labels:
#             ttk.label(frame, text=text).pack(anchor="w", pady=2)
#             entry = ttk.entry(frame, width=95)
#             entry.pack(pady=2)
#             self.gen_entries[text] = entry

#         btns = ttk.frame(frame)
#         btns.pack(pady=10)
#         ttk.button(btns, text="ngẫu nhiên", command=self.random_primes).pack(side="left", padx=6)
#         ttk.button(btns, text="tính toán", command=self.calculate_keys).pack(side="left", padx=6)
#         ttk.button(btns, text="xóa", command=self.clear_gen_tab).pack(side="left", padx=6)

#     def random_primes(self):
#         try:
#             # 1.tạo và hiển thị khóa mô phỏng
#             self.simple_rsa.random_primes()
#             self.show_rsa_info()
            
#             # 2.tự động tạo và lưu khóa thật
#             self._generate_and_save_real_keys()
#         except exception as e:
#             messagebox.showerror("lỗi", f"tạo khóa ngẫu nhiên thất bại: {e}")

#     def calculate_keys(self):
#         try:
#             # 1.lấy p, q và hiển th
#             p = int(self.gen_entries["p (số nguyên tố):"].get())
#             q = int(self.gen_entries["q (số nguyên tố):"].get())
#             self.simple_rsa.p = p
#             self.simple_rsa.q = q
#             self.simple_rsa.calculate_keys()
#             self.show_rsa_info()
            
#             # 2.tự động tạo key và lưu khóa
#             self._generate_and_save_real_keys()
#         except exception as e:
#             messagebox.showerror("lỗi", str(e))

#     def show_rsa_info(self):
#         info = self.simple_rsa.export_info()
#         for k, v in zip(self.gen_entries.keys(), info.values()):
#             self.gen_entries[k].delete(0, tk.end)
#             self.gen_entries[k].insert(0, v)

#     def clear_gen_tab(self):
#         for entry in self.gen_entries.values():
#             entry.delete(0, tk.end)
#         # cũng nên reset lại đối tượng rsa mô phỏng
#         self.simple_rsa = simplersa()

#     def _generate_and_save_real_keys(self):
#         try:
#             # 1. tạo khóa
#             key = rsakeymanager.generate_keypair(2048)
#             self.private_key = key
#             self.public_key = key.publickey()

#             # 2. định nghĩa đường dẫn
#             pub_path = "public_key.pem"
#             priv_path = "private_key.pem"

#             # 3. lưu file
#             rsakeymanager.save_key_to_file(rsakeymanager.export_public_key(self.public_key), pub_path)
#             rsakeymanager.save_key_to_file(rsakeymanager.export_private_key(self.private_key), priv_path)
            
#             # 4.thông báo cho người dùng
#             messagebox.showinfo("tạo khóa thành công",
#                                 f"- {os.path.abspath(pub_path)}\n"
#                                 f"- {os.path.abspath(priv_path)}\n\n")
#         except exception as e:
#             messagebox.showerror("lỗi lưu khóa tự động", f"không thể tạo hoặc lưu khóa .pem: {e}")


#     #ky so
#     def build_tab_sign(self):
#         frame = ttk.labelframe(self.tab_sign, text="ký tài liệu (rsa thật + sha-256)", padding=10)
#         frame.pack(fill="both", expand=true, padx=10, pady=10)

#         # data area
#         ttk.label(frame, text="dữ liệu cần ký:").grid(row=0, column=0, sticky="w")
#         ttk.button(frame, text="tải file", command=self.load_file_to_sign).grid(row=0, column=1, sticky="w", padx=6)
#         self.text_data = tk.text(frame, width=105, height=14)
#         self.text_data.grid(row=1, column=0, columnspan=4, pady=6)

#         # key 
#         ttk.button(frame, text="tải khóa bí mật (.pem)", command=self.load_private_key_from_file).grid(row=2, column=0, sticky="w", pady=6)
#         ttk.button(frame, text="ký tài liệu & tự động lưu", command=self.sign_data).grid(row=2, column=1, sticky="w", pady=6)
#         ttk.button(frame, text="xóa", command=self.clear_sign_tab).grid(row=2, column=2, sticky="w", pady=6)

#         #signature
#         ttk.label(frame, text="băm (sha-256):").grid(row=3, column=0, sticky="w", pady=(8,0))
#         self.hash_entry = ttk.entry(frame, width=100)
#         self.hash_entry.grid(row=4, column=0, columnspan=4, pady=4)

#         ttk.label(frame, text="chữ ký (hex):").grid(row=5, column=0, sticky="w", pady=(8,0))
#         self.signature_text = tk.text(frame, width=105, height=6)
#         self.signature_text.grid(row=6, column=0, columnspan=4, pady=6)

#     def load_file_to_sign(self):
#         path = filedialog.askopenfilename(title="chọn file cần ký")
#         if not path:
#             return
#         try:
#             with open(path, "r", encoding="utf-8") as f:
#                 txt = f.read()
#             self.text_data.delete("1.0", tk.end)
#             self.text_data.insert("1.0", txt)
#             self._sign_file_path = none
#         except exception:
#             # binary
#             self.text_data.delete("1.0", tk.end)
#             self.text_data.insert("1.0", f"[binary file selected: {path}]")
#             self._sign_file_path = path

#     def load_private_key_from_file(self):
#         file = filedialog.askopenfilename(title="chọn khóa bí mật (.pem)", filetypes=[("pem files", "*.pem"), ("all files", "*.*")])
#         if not file:
#             return
#         try:
#             self.private_key = rsakeymanager.load_key_from_file(file)
#             # tự động cập nhật public key tương ứng
#             self.public_key = self.private_key.publickey()
#             messagebox.showinfo("thành công", "đã tải khóa bí mật thành công! khóa công khai cũng đã được cập nhật.")
#         except exception as e:
#             messagebox.showerror("lỗi", f"tải khóa thất bại: {e}")

#     def sign_data(self):
#         # 1. chuẩn bị dữ liệu
#         if hasattr(self, "_sign_file_path") and self._sign_file_path:
#             with open(self._sign_file_path, "rb") as f:
#                 data = f.read()
#         else:
#             text = self.text_data.get("1.0", tk.end).rstrip("\n")
#             data = text.encode("utf-8")

#         if not data:
#             messagebox.showwarning("thiếu dữ liệu", "không có dữ liệu để ký.")
#             return

#         if not self.private_key:
#             messagebox.showwarning("chưa có khóa bí mật", "bạn chưa tải khóa bí mật, hoặc chưa tạo khóa ở tab 1.")
#             return

#         # 2. ký dữ liệu
#         signer = signer(self.private_key)
#         signature = signer.sign(data)
#         self._last_signature = signature 

#         # 3. hiển thị kết quả
#         self.hash_entry.delete(0, tk.end)
#         self.hash_entry.insert(0, signer.digest_hex(data))
#         self.signature_text.delete("1.0", tk.end)
#         self.signature_text.insert("1.0", signature.hex())
        
#         # 4. tự động lưu file
#         try:
#             # xác định tên file gốc và lưu dữ liệu gốc
#             data_filename = ""
#             if hasattr(self, "_sign_file_path") and self._sign_file_path:
#                 # lấy phần mở rộng của file gốc để lưu
#                 base_name = os.path.basename(self._sign_file_path)
#                 ext = os.path.splitext(base_name)[1]
#                 data_filename = f"signed_data{ext}" if ext else "signed_data.bin"
#             else:
#                 data_filename = "signed_data.txt"
            
#             # lưu dữ liệu
#             with open(data_filename, "wb") as f:
#                 f.write(data) 

#             # lưu chữ ký
#             sig_filename = "signature.sig"
#             with open(sig_filename, "wb") as f:
#                 f.write(signature)

#             # 5. thông báo thành công
#             messagebox.showinfo("ký số thành công",
#                                 f"đã ký tài liệu thành công.\n\n"
#                                 f"dữ liệu gốc đã lưu vào: {os.path.abspath(data_filename)}\n"
#                                 f"chữ ký đã lưu vào: {os.path.abspath(sig_filename)}")

#         except exception as e:
#             # nếu ký thành công nhưng lưu file lỗi
#             messagebox.showerror("lỗi lưu file", f"ký thành công, nhưng không thể tự động lưu file: {e}")

#     def clear_sign_tab(self):
#         self.text_data.delete("1.0", tk.end)
#         self.hash_entry.delete(0, tk.end)
#         self.signature_text.delete("1.0", tk.end)
#         self._sign_file_path = none
#         self._last_signature = none



#     #verify
#     def build_tab_verify(self):
#         frame = ttk.labelframe(self.tab_verify, text="xác minh chữ ký", padding=10)
#         frame.pack(fill="both", expand=true, padx=10, pady=10)

#         ttk.label(frame, text="dữ liệu cần xác minh:").grid(row=0, column=0, sticky="w")
#         ttk.button(frame, text="tải file", command=self.load_verify_file).grid(row=0, column=1, sticky="w", padx=6)
#         ttk.button(frame, text="tải chữ ký (.sig)", command=self.load_signature_from_file).grid(row=0, column=2, sticky="w", padx=6)
#         self.text_verify = tk.text(frame, width=105, height=14)
#         self.text_verify.grid(row=1, column=0, columnspan=4, pady=6)

#         ttk.label(frame, text="chữ ký (hex):").grid(row=2, column=0, sticky="w", pady=(6,0))
#         self.verify_sig_entry = ttk.entry(frame, width=96)
#         self.verify_sig_entry.grid(row=3, column=0, columnspan=3, pady=4, sticky="w")

#         ttk.button(frame, text="tải khóa công khai (.pem)", command=self.load_public_key_from_file).grid(row=4, column=0, sticky="w", pady=6)
#         ttk.button(frame, text="xác minh chữ ký", command=self.verify_signature).grid(row=4, column=1, sticky="w", pady=6)
#         ttk.button(frame, text="xóa", command=self.clear_verify_tab).grid(row=4, column=2, sticky="w", pady=6)

#         self.result_var = tk.stringvar(value="chưa xác minh")
#         ttk.entry(frame, textvariable=self.result_var, state="readonly", width=96).grid(row=5, column=0, columnspan=4, pady=6)

#     def load_verify_file(self):
#         # tải file dữ liệu gốc
#         default_file = "signed_data.txt"
#         if not os.path.exists(default_file):
#             if os.path.exists("signed_data.bin"):
#                 default_file = "signed_data.bin"
        
#         path = filedialog.askopenfilename(title="chọn file để xác minh", initialfile=default_file)
#         if not path:
#             return
#         try:
#             with open(path, "r", encoding="utf-8") as f:
#                 txt = f.read()
#             self.text_verify.delete("1.0", tk.end)
#             self.text_verify.insert("1.0", txt)
#             self._verify_file_path = none
#         except exception:
#             self.text_verify.delete("1.0", tk.end)
#             self.text_verify.insert("1.0", f"[binary file selected: {path}]")
#             self._verify_file_path = path

#     def load_signature_from_file(self):
#         # tải file chữ ký
#         default_file = "signature.sig"
#         path = filedialog.askopenfilename(title="chọn file chữ ký (.sig)", initialfile=default_file, filetypes=[("signature files", "*.sig"), ("all files", "*.*")])
#         if not path:
#             return
#         try:
#             with open(path, "rb") as f:
#                 sig = f.read()

#             self.verify_sig_entry.delete(0, tk.end)
#             self.verify_sig_entry.insert(0, sig.hex())
#             self._loaded_signature_bytes = sig 
#             messagebox.showinfo("tải chữ ký", "đã tải chữ ký từ file.")
#         except exception as e:
#             messagebox.showerror("lỗi", f"tải chữ ký thất bại: {e}")

#     def load_public_key_from_file(self):
#         # tải file khóa
#         default_file = "public_key.pem"
#         file = filedialog.askopenfilename(title="chọn khóa công khai (.pem)", initialfile=default_file, filetypes=[("pem files", "*.pem"), ("all files", "*.*")])
#         if not file:
#             return
#         try:
#             self.public_key = rsakeymanager.load_key_from_file(file)
#             messagebox.showinfo("thành công", "đã tải khóa công khai thành công!")
#         except exception as e:
#             messagebox.showerror("lỗi", f"tải khóa thất bại: {e}")

#     def verify_signature(self):
      
#         if hasattr(self, "_verify_file_path") and self._verify_file_path:
#             with open(self._verify_file_path, "rb") as f:
#                 data = f.read()
#         else:
#             text = self.text_verify.get("1.0", tk.end).rstrip("\n")
#             data = text.encode("utf-8")

#         if not data:
#             messagebox.showwarning("thiếu dữ liệu", "bạn chưa cung cấp dữ liệu để xác minh.")
#             return

#         # signature bytes
#         sig_bytes = none
#         if hasattr(self, "_loaded_signature_bytes") and self._loaded_signature_bytes:
#             sig_bytes = self._loaded_signature_bytes
#             self._loaded_signature_bytes = none 
#         else:
#             hex_text = self.verify_sig_entry.get().strip()
#             if not hex_text:
#                 messagebox.showwarning("thiếu chữ ký", "bạn chưa cung cấp chữ ký để xác minh.")
#                 return
#             try:
#                 sig_bytes = bytes.fromhex(hex_text)
#             except exception:
#                 messagebox.showerror("lỗi", "chữ ký không hợp lệ (không phải hex).")
#                 return

#         if not self.public_key:
#             messagebox.showwarning("thiếu khóa", "bạn chưa tải khóa công khai (hãy tạo ở tab 1 hoặc tải lên).")
#             return

#         verifier = verifier(self.public_key)
#         try:
#             ok = verifier.verify(data, sig_bytes)
#             self.result_var.set("Hợp lệ" if ok else "không hợp lệ")
#             if ok:
#                 messagebox.showinfo("kết quả", "chữ ký hợp lệ.")
#             else:
#                 messagebox.showwarning("kết quả", "chữ ký không hợp lệ.")
#         except exception as e:
#             messagebox.showerror("lỗi", f"xác minh thất bại: {e}")

#     def clear_verify_tab(self):
#         self.text_verify.delete("1.0", tk.end)
#         self.verify_sig_entry.delete(0, tk.end)
#         self.result_var.set("chưa xác minh")
#         self._loaded_signature_bytes = none
#         self._verify_file_path = none


# # main
# if __name__ == "__main__":
#     app = rsasignatureapp()
#     app.mainloop()