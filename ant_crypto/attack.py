from tool import *
from cipher import *
import string
import random

class ECB_CPA:
    def __init__(self, offset:int, end, oracle, table:bytes=string.printable[:94].encode(), pad=pad, block_size=16):
        self.offset = offset
        self.end = end
        self.oracle = oracle
        self.table = list(table)
        self.pad = pad
        self.block_size = block_size

        self.pt = bytes()

    def run(self,debug:bool=False) -> bytes:
        while self.end(self.pt):
            random.shuffle(self.table)
            for i in self.table:
                pay = bytes([i])
                pay += self.pt
                pay = self.pad(pay)
                k = len(pay)
                pay += b'\x00'*(self.offset+len(self.pt))
                
                c = self.oracle(pay)
            
                if c[:k] == c[-k:]:
                    self.pt = bytes([i]) + self.pt
                    if debug:print(f'[DEBUG] {self.pt}')
                    break
            if debug:print('[DEBUG] NEXT!')
        
        if debug:print('[DEBUG] DONE!')
        return self.pt

class CBC_OPA:
    def __init__(self, oracle,  pad=pad, block_size:int=16):
        self.oracle = oracle
        self.pad = pad
        self.block_size = block_size


    def run(self, iv:bytes,ct:bytes,debug:bool=False) -> bytes:
        pad_list = [self.pad(b'A'*i)[-1] for i in range(self.block_size)]
        
        cts = [ct[i:i+self.block_size] for i in range(0,len(ct),self.block_size)]

        pt = iv
        for i in range(len(cts)):
            iv = pt[-self.block_size:]
            ct = cts[i]

            last_block = [ord(' ') for _ in range(self.block_size)]
            for j in range(self.block_size - 1, -1, -1):
                now_byte = ct[j]
                now_count = self.block_size - j
                now_pad = pad_list[j]

                for k in range(1,256):
                    pay_c = bytes(list(iv[:j])+[k ^ now_pad]+[x^now_pad for x in last_block[j+1:]])

                    if self.oracle(pay_c, ct):
                        last_block[j] = k
                        if debug:print(f'[DEBUG] {bytes(last_block)}')
                        break
            
            if i == 0:
                pt = bytes()
            
            pt += bytes(last_block)

            if debug:print(f"[DEBUG] {pt}")
        
        return pt



class RSA_LSB_ORACLE_ATTACK:
    def __init__(self,get,oracle):
        self.get = get
        self.oracle = oracle
    
    def run(self,start:int,init_N:int,pt_enc:int,debug:bool=False) -> int:
        bits = str(self.oracle(self.get()['ct']))
        i = 1
        while True:
            key = self.get()
            N = key['N']
            e = key['e']
            enc = key['ct']

            inv = mod_inverse(2**i, N)
            chosen_ct = (enc*pow(inv, e, N))%N
            output = self.oracle(chosen_ct)
            flag_char = (output - ((int(bits, 2)*inv) % N)) % 2
        
            bits = str(flag_char) + bits
            if debug and len(bits) % 8 == 0:
                pt = num_to_bytes(int(bits, 2))
                print(pt)
            if pt_enc == pow(int(bits, 2), e, init_N):
                break
            i+=1
        
        return int(bits,2)


__table = {
' ' : 18.28846265,
'E' : 10.26665037,
'T' : 7.51699827,
'A' : 6.53216702,
'O' : 6.15957725,
'N' : 5.71201113,
'I' : 5.66844326,
'S' : 5.31700534,
'R' : 4.98790855,
'H' : 4.97856396,
'L' : 3.31754796,
'D' : 3.28292310,
'U' : 2.27579536,
'C' : 2.23367596,
'M' : 2.02656783,
'F' : 1.98306716,
'W' : 1.70389377,
'G' : 1.62490441,
'P' : 1.50432428,
'Y' : 1.42766662,
'B' : 1.25888074,
'V' : 0.79611644,
'K' : 0.56096272,
'X' : 0.14092016,
'J' : 0.09752181,
'Q' : 0.08367550,
'Z' : 0.05128469,
}

def __scoring(x):
    score = 0
    for i in x:
         i = chr(i).upper()
         if i in table:
             score += table[i]
        
    return score

def __recover(x):
    maxScore = 0
    ret = None
    for i in range(256):
        c = xor(x,[i]*len(x))
        score = __scoring(c)
        
        if maxScore < score:
            ret = i
            maxScore = score

    return ret

def __getKey(t):
    maxLen = max([len(i) for i in t])
    ret = bytes()
    for i in range(maxLen):
        block = []
        for j in t:
            if len(j) > i:
                block.append(j[i])    
        ret += bytes([__recover(block)])
    return ret


def CTR_XOR_BREAK(ciphertext_list) -> list:
    key = getKey(ciphertext_list)
    return [xor(i^key) for i in ciphertext_list]


