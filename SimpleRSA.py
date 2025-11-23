import math
import random

class SimpleRSA:
    def __init__(self):
        self.p = None
        self.q = None
        self.n = None
        self.phi_n = None
        self.e = None
        self.d = None

    def is_prime(self, num):
        if num is None: return False
        if num < 2: return False
        for i in range(2, int(math.sqrt(num)) + 1):
            if num % i == 0:
                return False
        return True

    def random_primes(self):
        primes = [i for i in range(100, 500) if self.is_prime(i)]
        self.p, self.q = random.sample(primes, 2)
        self.calculate_keys()

    def calculate_keys(self):
        if not self.p or not self.q:
            raise ValueError("Chưa có p, q")
        if not self.is_prime(self.p) or not self.is_prime(self.q):
            raise ValueError("p hoặc q không phải số nguyên tố")
        if self.p == self.q:
            raise ValueError("p và q không được bằng nhau")

        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        try:
            self.e = next(e for e in (3,5,17,257,65537) if e < self.phi_n and math.gcd(e, self.phi_n) == 1)
        except StopIteration:
            self.e = next(e for e in range(3, self.phi_n) if math.gcd(e, self.phi_n) == 1)
        self.d = pow(self.e, -1, self.phi_n)

    def export_info(self):
        return {
            "p": self.p,
            "q": self.q,
            "n": self.n,
            "phi_n": self.phi_n,
            "e": self.e,
            "d": self.d,
            "public_key": f"({self.n}, {self.e})",
            "private_key": f"({self.n}, {self.d})"
        }