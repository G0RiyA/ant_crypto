 
from tool import *
import string

__all__ = ['ROT5','ROT13','ROT18','ROT47','Scytale','RSA','AES']

def ROT5(plaintext :bytes, count :int = 5) -> bytes:
    count %= 10
    table = string.digits
    table = table[:count] + table[count:] 

    trans = bytes.maketrans(string.digits.encode(),table.encode())
    return plaintext.translate(trans)

def ROT13(plaintext :bytes, count :int = 13) -> bytes:
    count %= 26
    table = string.ascii_lowercase
    table = table[:count] + table[count:]

    trans = bytes.maketrans((string.ascii_lowercase + string.ascii_uppercase).encode(), (table + table.upper()).encode())
    return plaintext.translate(trans)

def ROT18(plaintext :bytes, alphabet_count :int = 13, digits_count :int = 5) -> bytes:
    return ROT5(ROT13(plaintext,alphabet_count),digits_count)

def ROT47(plaintext :bytes, count :int = 47) -> bytes:
    count %= 94
    ROT47_table = '''!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~'''
    table = ROT47_table[:count] + ROT47_table[count:]

    trans = bytes.maketrans(ROT47_table,table)
    return plaintext.translate(trans)

class Scytale:
    def __init__(self, band :int):
        self.band = band
    
    def _pad(self, text :bytes) -> bytes:
        return text + b' '*((self.band - (len(text) % self.band)) % self.band)

    def encrypt(self, plaintext :bytes) -> bytes:
        plaintext = self._pad(plaintext)
        ciphertext = [0x20 for _ in range(len(plaintext))]

        gap = len(plaintext) // self.band
        index = 0
        count = 1
        for char in plaintext:
            ciphertext[index] = char
            index += gap
            if index >= len(ciphertext):
                index = count
                count += 1
        
        return bytes(ciphertext)

    def decrypt(self, ciphertext :bytes) -> bytes:
        ciphertext = self._pad(ciphertext)
        plaintext = []

        gap = len(ciphertext) // self.band
        index = 0
        count = 1
        while len(plaintext) < len(ciphertext):
            plaintext.append(ciphertext[index])
            index += gap
            if index >= len(ciphertext):
                index = count
                count += 1
        
        return bytes(plaintext)

class RSA:
    def __init__(self,n=None,p=None,q=None,e=None,d=None):
        self.n = n
        self.p = p
        self.q = q
        self.e = e
        self.d = d

        if self.n is not None and self.p is None and self.q is not None:
            self.p = self.n // self.q

        if self.n is not None and self.q is None and self.p is not None:
            self.q = self.n // self.p

        if self.n is None and self.p is not None and self.q is not None:
            self.n = p*q
        
        if self.d is None and self.p is not None and self.q is not None and self.e is not None:
            phi = (self.p - 1) * (self.q - 1)
            self.d = mod_inverse(self.e, phi)
        
        assert n is not None and (e is not None or d is not None)
    
    def encrypt(self, message :int):
        assert self.e is not None
        return pow(message, self.e, self.n)
    
    def decrypt(self, cipher :int):
        assert self.d is not None
        return pow(cipher, self.d, self.n)

class AES:
    
    
    @staticmethod
    def __xtime(a):
        return(((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

    __s_box = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )

    __inv_s_box = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    )

    @staticmethod
    def __matrix2bytes(matrix):
        return b''.join([bytes(i) for i in matrix])

    @staticmethod
    def __bytes2matrix(text):
        return [list(text[i:i+4]) for i in range(0, len(text), 4)]

    @staticmethod
    def __add_round_key(s, k):
        for i in range(4):
            for j in range(4):
                s[i][j] ^= k[i][j]

    @staticmethod
    def __sub_bytes(s):
        for i in range(4):
            for j in range(4):
                s[i][j] = AES.__s_box[s[i][j]]

    @staticmethod
    def __inv_sub_bytes(s):
        for i in range(4):
            for j in range(4):
                s[i][j] = AES.__inv_s_box[s[i][j]]

    @staticmethod
    def __inv_mix_columns(s):
        for i in range(4):
            u = AES.__xtime(AES.__xtime(s[i][0] ^ s[i][2]))
            v = AES.__xtime(AES.__xtime(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v

        AES.__mix_columns(s)

    @staticmethod
    def __mix_single_column(a):
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ AES.__xtime(a[0] ^ a[1])
        a[1] ^= t ^ AES.__xtime(a[1] ^ a[2])
        a[2] ^= t ^ AES.__xtime(a[2] ^ a[3])
        a[3] ^= t ^ AES.__xtime(a[3] ^ u)

    @staticmethod
    def __mix_columns(s):
        for i in range(4):
            AES.__mix_single_column(s[i])

    @staticmethod
    def __shift_rows(s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


    @staticmethod
    def __inv_shift_rows(s):
        s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3]
        s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
        s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]


    def __init__(self,key:bytes=None,iv:bytes=None,counter=None):
        assert key is not None
        assert len(key) == 16

        self.__N_ROUNDS = 10
        self.__round_keys = self.__expand_key(key)
        self.__KEY_SIZE = 128
        self.__key = key
        
        self.iv = iv
        self.counter = counter


    def __expand_key(self, master_key :bytes):

        r_con = (
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
            0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
            0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
        )

        key_columns = self.__bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        columns_per_iteration = len(key_columns)
        i = 1
        while len(key_columns) < (self.__N_ROUNDS + 1) * 4:
            word = list(key_columns[-1])

            if len(key_columns) % iteration_size == 0:
                word.append(word.pop(0))
                word = [self.__s_box[b] for b in word]
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                word = [self.__s_box[b] for b in word]

            word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
            key_columns.append(word)

        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]


    def __decrypt(self, ciphertext :bytes) -> bytes:
        assert len(ciphertext) == self.__KEY_SIZE // 8
        plaintext = self.__bytes2matrix(ciphertext)

        self.__add_round_key(plaintext,self.__round_keys[-1])
        self.__inv_shift_rows(plaintext)
        self.__inv_sub_bytes(plaintext)

        for i in range(self.__N_ROUNDS - 1, 0, -1):
            self.__add_round_key(plaintext,self.__round_keys[i])
            self.__inv_mix_columns(plaintext)
            self.__inv_shift_rows(plaintext)
            self.__inv_sub_bytes(plaintext)
            
        self.__add_round_key(plaintext,self.__round_keys[0])
        plaintext = self.__matrix2bytes(plaintext)
        return plaintext

    def __encrypt(self, plaintext :bytes) -> bytes:
        assert len(plaintext) == self.__KEY_SIZE // 8
        ciphertext = self.__bytes2matrix(plaintext)

        self.__add_round_key(ciphertext,self.__round_keys[0])
        for i in range(1,self.__N_ROUNDS):
            self.__sub_bytes(ciphertext)
            self.__shift_rows(ciphertext)
            self.__mix_columns(ciphertext)
            self.__add_round_key(ciphertext,self.__round_keys[i])
        
        self.__sub_bytes(ciphertext)
        self.__shift_rows(ciphertext)
        self.__add_round_key(ciphertext,self.__round_keys[-1])

        ciphertext = self.__matrix2bytes(ciphertext)
        return ciphertext
    
    def encrypt_ecb(self, plaintext :bytes) -> bytes:
        assert len(plaintext) % (self.__KEY_SIZE // 8) == 0
        block_size = self.__KEY_SIZE // 8

        ciphertext = bytes()
        for i in range(0,len(plaintext),block_size):
            ciphertext += self.__encrypt(plaintext[i:i+block_size])
        
        return ciphertext
    
    def decrypt_ecb(self, ciphertext :bytes) -> bytes:
        assert len(ciphertext) % (self.__KEY_SIZE // 8) == 0
        block_size = self.__KEY_SIZE // 8

        plaintext = bytes()
        for i in range(0,len(ciphertext),block_size):
            plaintext += self.__decrypt(ciphertext[i:i+block_size])
        
        return plaintext

    def encrypt_cbc(self, plaintext :bytes) -> bytes:
        assert len(plaintext) % (self.__KEY_SIZE // 8) == 0
        assert self.iv is not None
        assert len(self.iv) == len(self.__key)
        block_size = self.__KEY_SIZE // 8

        iv = self.iv
        ciphertext = bytes()
        
        for i in range(0,len(plaintext),block_size):
            block = self.__encrypt(xor(plaintext[i:i+block_size],iv))
            ciphertext += block
            iv = block
        
        return ciphertext
    
    def decrypt_cbc(self, ciphertext :bytes) -> bytes:
        assert len(ciphertext) % (self.__KEY_SIZE // 8) == 0
        assert self.iv is not None
        assert len(self.iv) == len(self.__key)
        block_size = self.__KEY_SIZE // 8
        
        iv = self.iv
        plaintext = bytes()
        for i in range(0,len(ciphertext),block_size):
            block = self.__decrypt(ciphertext[i:i+block_size])
            plaintext += xor(block,iv)
            iv = ciphertext[i:i+block_size]

        return plaintext
    
    def encrypt_ofb(self, plaintext :bytes) -> bytes:
        assert len(plaintext) % (self.__KEY_SIZE // 8) == 0
        assert self.iv is not None
        assert len(self.iv) == len(self.__key)
        block_size = self.__KEY_SIZE // 8

        iv = self.iv
        ciphertext = bytes()
        for i in range(0,len(plaintext),block_size):
            iv = self.__encrypt(iv)
            ciphertext += xor(plaintext[i:i+16],iv)
        
        return ciphertext
    
    def decrypt_ofb(self, ciphertext :bytes) -> bytes:
        assert len(ciphertext) % (self.__KEY_SIZE // 8) == 0
        assert self.iv is not None
        assert len(self.iv) == len(self.__key)
        
        return self.encrypt_ofb(ciphertext)

    def encrypt_cfb(self, plaintext :bytes) -> bytes:
        assert len(plaintext) % (self.__KEY_SIZE // 8) == 0
        assert self.iv is not None
        assert len(self.iv) == len(self.__key)
        block_size = self.__KEY_SIZE // 8

        iv = self.iv
        ciphertext = bytes()
        for i in range(0,len(plaintext),block_size):
            block = xor(plaintext[i:i+16],self.__encrypt(iv))
            ciphertext += block
            iv = block
        
        return ciphertext


    def decrypt_cfb(self, ciphertext :bytes) -> bytes:
        assert len(ciphertext) % (self.__KEY_SIZE // 8) == 0
        assert self.iv is not None
        assert len(self.iv) == len(self.__key)
        block_size = self.__KEY_SIZE // 8

        iv = self.iv
        plaintext = bytes()
        for i in range(0,len(ciphertext),block_size):
            iv = self.__encrypt(iv)
            plaintext += xor(ciphertext[i:i+16],iv)
            iv = ciphertext[i:i+16]
        
        return plaintext
    
    def encrypt_ctr(self, plaintext :bytes) -> bytes:
        assert len(plaintext) % (self.__KEY_SIZE // 8) == 0
        assert self.iv is not None
        assert len(self.iv) == len(self.__key)
        block_size = self.__KEY_SIZE // 8
        
        nonce = self.iv
        ciphertext = bytes()
        for i in range(0,len(plaintext),16):
            ciphertext += xor(plaintext[i:i+16],self.__encrypt(nonce))
            nonce = (1+bytes_to_num(nonce)).to_bytes(self.__KEY_SIZE // 8,'big')
        
        return ciphertext
    
    def decrypt_ctr(self, ciphertext :bytes) -> bytes:
        assert len(ciphertext) % (self.__KEY_SIZE // 8) == 0
        assert self.iv is not None
        assert len(self.iv) == len(self.__key)
        block_size = self.__KEY_SIZE // 8

        return self.encrypt_ctr(ciphertext)