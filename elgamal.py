import math
import random
import time
import sympy

PRIMES_55 = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257]

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def is_primitive_root(g, p):
    if pow(g, (p-1)//2, p) == 1:
        return False
    if pow(g, 2, p) == 1:
        return False
    return True

def find_primitive(p):
    while True:
        g = random.randint(2, p-1)
        if is_primitive_root(g, p):
            return g
        
def jacobi(a, m):
    result = 1
    a = a % m
    while a != 0:
        while a % 2 == 0:
            a //= 2
            if m % 8 in [3, 5]:
                result = -result
        a, m = m, a
        if a % 4 == 3 and m % 4 == 3:
            result = -result
        a = a % m
    if m == 1:
        return result
    return 0

def mod_exp(x, a, m):
    result = 1
    while a > 0:
        if a % 2 == 1:
            result = (result * x) % m
        x = (x ** 2) % m
        a = a // 2
    return result

def solovay_strassen(n, k, bits):
    for _ in range(k):
        # check if a is == +-1
        a = random.getrandbits(bits)
        if gcd(a, n) != 1:
            return False
        x = jacobi(a, n)
        y = mod_exp(a, (n - 1) // 2, n)
        if y != 1 and y != n - 1:
            return False
        if y != x % n:
            return False
    return True

def sophie_germain(bits, trials):
    sg = 0
    
    count_primes = 0
    # works to decrease running time by initially finding a number that is "probably" prime
    while True:
        sg = random.getrandbits(bits - 2)
        sg = ((sg << 1) ^ 1) ^ (1 << bits - 1)
        
        if all(sg % prime != 0 for prime in PRIMES_55):
            # finds a Sophie Germain using Solovay-Strassen primality testing
            if solovay_strassen(sg, trials, bits):
                count_primes += 1
                if solovay_strassen(2 * sg + 1, trials, bits):
                    safe = 2 * sg + 1
                    return sg, safe, count_primes

def mod_inverse(a, m):
    gcd, x = extended_gcd(a, m)
    if gcd == 1:
        return x % m
    return None

def extended_gcd(a, m):
    old_remainder, remainder = a, m
    old_x, x = 1, 0
    old_y, y = 0, 1
    
    while remainder != 0:
        quotient = old_remainder // remainder
        old_remainder, remainder = remainder, old_remainder - quotient * remainder
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y

    return old_remainder, old_x

def generate_key(bits, trials):
    # finds a random Sophie Germain prime of a certain bit length
    sg, safe, num_primes = sophie_germain(bits, trials)
    # find a primitive root of p in the cyclic group of the safe prime
    prim = find_primitive(safe)

    # computes the key
    g = pow(prim, 2, sg)
    x = random.randint(1, safe - 1)
    h = pow(g, x, sg)
    
    # note the format for the public and private key
    public = (sg, g, h)
    private = (sg, g, x)
    
    return public, private, num_primes
    
# works to encrypt using the El Gamal encryption
def encrypt(key, message):
    p, g, h = key
    k = random.randint(1, p - 1)
    c1 = pow(g, k, p)
    c2 = (message * pow(h, k, p)) % p
    return c1, c2

# works to decrypt using the El Gamal decryption
def decrypt(key, c1, c2):
    p, _, x = key
    s = pow(c1, x, p)
    s_inverse = mod_inverse(s, p)
    message = (c2 * s_inverse) % p
    return message

# converts a string to byte representation of ASCII characters
def str_to_num(message):
    message_bytes = message.encode('ascii', errors='ignore')
    message_number = int.from_bytes(message_bytes, byteorder='big')
    return message_number

# converts a number to a string of ASCII characters
def numb_to_str(number):
    num_bytes = (number.bit_length() + 7) // 8
    message_bytes = number.to_bytes(num_bytes, byteorder='big')
    message = message_bytes.decode('ascii', errors='ignore')
    return message

def main():
    print("Choose whether to encrypt, decrypt, or generate a key")
    choice = input("Please enter 'e', 'd', or 'g': ")
    
    # encrypt code
    if choice == 'e':
        print("Reading a message from 'elgamalplaintext.txt'")
        plaintext = open('elgamalplaintext.txt', 'r').read()
        plaintext_num = str_to_num(plaintext)
        
        # pulls the key from file
        keys = open('elgamalpublickey.txt', 'r').readlines()
        p = int(keys[0].strip())
        g = int(keys[1].strip())
        h = int(keys[2].strip())
        
        # gives the shared key and message
        c1, c2 = encrypt((p, g, h), plaintext_num)
        
        # writes ciphertext to file
        with open('elgamalciphertext.txt', 'w') as file:
            file.write(f"{c1}\n")
            file.write(f"{c2}\n")
        print("Written to 'elgamalciphertext.txt'")
    
    # decrypt code
    elif choice == 'd':
        print("Reading code from 'elgamalciphertext.txt")
        ciphertext = open('elgamalciphertext.txt', 'r').readlines()
        c1 = int(ciphertext[0].strip())
        c2 = int(ciphertext[1].strip())
        
        key = open('elgamalprivatekey.txt', 'r').readlines()
        p = int(key[0].strip())
        g = int(key[1].strip())
        x = int(key[2].strip())
        
        decrypted_num = decrypt((p, g, x), c1, c2)
        message = numb_to_str(decrypted_num)
        
        print(f"Decrypted message:\n{message}")
        
    elif choice == 'g':
        bit_size = int(input("Input bit size: "))
        trials = int(input("Input number of trials: "))
        
        print("Generating keys and writing them to 'elgamalpublickey.txt' and 'elgamalprivatekey.txt'")
        start = time.time()
        pub, priv, num_primes = generate_key(bit_size, trials)
        end = time.time()
        print(f"Time taken: {end - start} seconds")
        print(f"Checked {num_primes} primes before finding a Sophie Germain prime")
        print(f"Confidence level given your key size and trials: {1 - ((bit_size * math.log(2) - 2)/(bit_size * math.log(2) - 2 + 2 ** (trials+1)))}")
        print("Public key written to 'elgamalpublickey.txt \nPrivate key written to 'elgamalprivatekey.txt")
        
        # writing to files
        with open('elgamalpublickey.txt', 'w') as file:
            file.write('\n'.join(map(str, pub)))
    
        with open('elgamalprivatekey.txt', 'w') as file:
            file.write('\n'.join(map(str, priv)))
    else:
        print("No choice chosen")
    
if __name__ == "__main__":
    main()