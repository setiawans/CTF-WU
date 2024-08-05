'''
This is an AES CBC challenge which encryption function actually does decryption process.
Using provided IV, we can recover fifth block by bruteforcing and first-fourth block by doing xor(xor(temp_iv[i], temp_ct[i]), ct[i-1])
The temp_iv[i] and temp_ct[i] is the result of encrypting pt[i]
'''

from pwn import *

def connect() :
    target = 'nc ctf.gemastik.id 10004'.split()
    return remote(target[1], target[2])

def get_flag() :
    p.recvuntil(b'This is the example of the encryption result: ')
    flag = p.recvline().strip().decode()
    return split_item(flag)

def encrypt_server(input) :
    p.recvuntil(b'Give me your message: ')
    input = input.hex().encode()
    p.sendline(input)
    p.recvuntil(b'Encryption result: ')
    enc = p.recvline().strip().decode()
    return split_item(enc)

def split_item(hex_str) :
    hex_str = bytes.fromhex(hex_str)
    return hex_str[:16], hex_str[16:]

def xor(a, b) :
    return bytes(a ^ b for a, b in zip(a, b))

def main() :
    global p 
    p = connect()

    flag_iv, flag_ct = get_flag()

    enc_block = []
    enc_block.append(flag_ct[:16])
    enc_block.append(flag_ct[16:32])
    enc_block.append(flag_ct[32:48])
    enc_block.append(flag_ct[48:64])
    enc_block.append(flag_ct[64:80])

    first_pt, sec_pt, third_pt, fourth_pt, fifth_pt = b'',b'',b'',b'',b''
    # Bruteforce fourth block and fifth block (last block)
    printable_ascii = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c'
    for i in printable_ascii :
        for j in printable_ascii :
            bf_block = bytes([i, j]) + b'}'
            enc_bf_block_iv, enc_bf_block_ct = encrypt_server(bf_block)
            temp = xor(enc_bf_block_iv, enc_bf_block_ct)
        
            if all([x in printable_ascii for x in xor(temp, enc_block[4])]) :
                fourth_pt = xor(temp, enc_block[4])
                fifth_pt = bf_block
                break

    # The rest of the xor-ing process is identical
    # Get third block
    temp_iv, temp_ct = encrypt_server(fourth_pt)
    temp = xor(temp_iv, temp_ct)
    third_pt = xor(temp, enc_block[3])

    # Get second block
    temp_iv, temp_ct = encrypt_server(third_pt)
    temp = xor(temp_iv, temp_ct)
    sec_pt = xor(temp, enc_block[2])

    # Get first block
    temp_iv, temp_ct = encrypt_server(sec_pt)
    temp = xor(temp_iv, temp_ct)
    first_pt = xor(temp, enc_block[1])

    flag = first_pt + sec_pt + third_pt + fourth_pt + fifth_pt
    print(flag)

if __name__ == "__main__" :
    main()