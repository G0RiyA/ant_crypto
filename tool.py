import math

def xor(x :bytes, y :bytes, repeat :bool=False) -> bytes:
    if repeat:
        if len(x) < len(y):
            x,y = y,x
        k = math.ceil((len(x) - len(y)) / len(y))
        y += y*k
    return bytes([i^j for i,j in zip(x,y)])

def gcd(a :int, b :int) -> int:
    while b > 0:
        a,b=b,a%b
    return a

def xgcd(a :int, b :int) -> tuple:
    x0,x1,y0,y1 = 1,0,0,1
    while b > 0:
        k, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - k * x1
        y0, y1 = y1, y0 - k * y1
    return x0, y0

def mod_inverse(x :int, n :int) -> int:
    return xgcd(x,n)[0] % n

def num_to_bytes(x :int) -> bytes:
    return x.to_bytes(math.ceil(x.bit_length()/8),byteorder='big')

def bytes_to_num(x :bytes) -> int:
    return int(x.hex(),16)

def chinese_remainder_thorem(a, n) -> int:
    N = 1
    for i in n:
        N *= i
    
    ret = 0
    for c,ni in zip(a,n):
        m = N//ni
        ret += m*c*mod_inverse(m,ni)
    
    ret %= N
    return ret

def pad(data :bytes, n:int=16) -> bytes:
    x = n - (len(data) % n)
    return data + bytes([x]*x)

def unpad(data :bytes, n:int=16) -> bytes:
    x = int(data[-1])
    assert 0 < x <= n and data[-x:] == bytes([x]*x)
    return data[:-x]
