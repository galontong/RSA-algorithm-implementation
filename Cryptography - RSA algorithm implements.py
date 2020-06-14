"""
This program implements the RSA algorithm for cryptography,
Converting messages of String as a number for use with the RSA encryption algorithm
and vice versa.
"""
import sympy as sy

def gcd(a, b): 
    if b == 0: 
        return a 
    else: 
        return gcd(b, a%b)

def convert_ascii(X):
    """custom converting a given variable to integer and vice versa

    Args:
        X (int or char): given variable that want to convert

    Returns:
        [int or char]: converted variable
    """
    if isinstance(X, str):
        x = ord(X)
        if(x < 97 or x > 122):  # ascii code for non alphabet
            x = 0               # convert non alphabet char to 0 or 'space'
        else:
            x -= 96
    elif isinstance(X, int):
        x = X
        if(x == 0):
            x += 32 # ascii code for space
        else:
            x += 96
        x = chr(x)
    return x

def i2osp(x, x_len):
    """converts a nonnegative integer(x) to an octet string(output) of a
   specified length(x_len)

    Args:
        x (integer): nonnegative integer to be converted
        x_len (integer): intended length of the resulting octet string

    Raises:
        ValueError: integer too large

    Returns:
        [String]: corresponding octet string of length xLen
    """
    if x >= 27 ** x_len:
        raise ValueError("integer too large")
    digits = []

    while x:
        digits.append(int(x % 27))
        x //= 27 # floor division operator

    for i in range(x_len - len(digits)): # note that one or more leading digits will be zero if x is less than 256^(xLen-1)
        digits.append(0)
    digits = digits[::-1]
    block_text = []
    for i in range(x_len):
        block_text.append(convert_ascii(digits[i]))
    return "".join(block_text)

def os2ip(X):
    """converts an octet string to a nonnegative integer

    Args:
        X (String): octet string to be converted

    Returns:
        integer: corresponding nonnegative integer
    """
    X = X[::-1] # reverse order
    x = 0
    for i in range(len(X)):
        x += convert_ascii(X[i]) * 27 ** i
    return x

def encrypt(m):
    """Encryption plaintext

    Args:
        m (String): message

    Returns:
        integer: ciphertext representative, an integer between 0 and n - 1
    """
    print("[ENCRYPTION]")
    m = m.lower()
    c = []
    block = ([m[i : i + BLOCK_LENGTH] for i in range(0, len(m), BLOCK_LENGTH)])
    print(block)
    for i in block:
        converted_block = os2ip(i)
        print(converted_block, end=", ")
        c.append((converted_block ** e) % n)
    print("")
    return c

def decrypt(c):
    """Decryption Ciphertext

    Args:
        c (array of integer): block of ciphertext representative, an integer between 0 and n - 1

    Returns:
        String: message
    """
    print("[DECRYPTION]")
    block_text = []
    for i in c:
        block = (i ** d) % n
        print(block, end=", ")
        block_text.append(i2osp(block, BLOCK_LENGTH))
    print("")
    m = "".join(block_text)
    return m

# Main
BLOCK_LENGTH = 3
p = 173
q = 149
n = p * q   # public key 1
t = (p - 1) * (q - 1)

if not sy.isprime(p) or not sy.isprime(q):
    raise ValueError("p or q is not prime number")

# public key 2
for e in range(2, t):
    if gcd(e, t) == 1: 
        break

# private key
k = 1
while(True):
    if (1 + k * t) % e == 0: 
        d = int((1 + k * t) / e) 
        break
    k += 1

print("[PULIC KEY]")
print("n = ", n)
print("e = ", e)
print("[PRIVATE KEY]")
print("d = ", d)
print("")



messages = "Tolong jangan siksa saya"
print("Messages = ", messages)
print("")

# ENCRYPT
cipher_text = encrypt(messages)
print(cipher_text)
print("")

# DECRYPT
plain_text = decrypt(cipher_text)
print(plain_text)
print("")
