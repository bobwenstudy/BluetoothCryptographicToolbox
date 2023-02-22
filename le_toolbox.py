from Crypto.Cipher import AES
import binascii
import random
import math
from EllipticCurve import *

# 加密函数
def encrypt(key, plain_text):
    mode = AES.MODE_ECB
    cryptos = AES.new(key, mode)

    cipher_text = cryptos.encrypt(plain_text)
    return cipher_text

# 解密函数
def decrypt(key, plain_text):
    mode = AES.MODE_ECB
    cryptos = AES.new(key, mode)

    cipher_text = cryptos.decrypt(plain_text)
    return cipher_text

def reverse_bytes(data_arr):
    tmpIndex = len(data_arr) - 1
    data_arr_tmp = b''
    for i in range(len(data_arr)):
        b = data_arr[tmpIndex - i]
        data_arr_tmp += b.to_bytes(length=1,byteorder='big',signed=False)

    return data_arr_tmp

def get_bytes_from_big_eddian_string(str):
    str = str.upper().replace('0X', '')
    return reverse_bytes(bytes.fromhex(str))

def reverse_bytes_enc(data_arr):
    tmpIndex = 15
    data_arr_tmp = b''
    for i in range(16):
        b = data_arr[(tmpIndex - i)*2 + 0]
        data_arr_tmp += b.to_bytes(length=1,byteorder='big',signed=False)
        b = data_arr[(tmpIndex - i)*2 + 1]
        data_arr_tmp += b.to_bytes(length=1,byteorder='big',signed=False)

    return data_arr_tmp

def xor_array(a_arr, b_arr):
    data_arr_tmp = b''
    for i in range(len(a_arr)):
        a = a_arr[i]
        b = b_arr[i]
        data_arr_tmp += (a^b).to_bytes(length=1,byteorder='big',signed=False)

    return data_arr_tmp


def int2bin_8(val):
    return '{:08b}'.format(val)

def bytes2bin(arr):
    tmp = ''
    for i in range(len(arr)):
        tmp += int2bin_8(arr[i])
    return tmp

def bin2bytes(bin_str):
    if len(bin_str) % 8 != 0:
        raise Exception("Error length")
    cnt = int(len(bin_str) / 8)

    tmp = b''
    for i in range(cnt):
        tmp += int(bin_str[i*8:((i+1)*8)], 2).to_bytes(length=1,byteorder='big',signed=False)
    
    return tmp

# input arr is little_endian
def lshift_array(arr, shift_cnt):
    arr = reverse_bytes(arr)
    tmp = bytes2bin(arr)
    tmp_len = len(tmp)
    tmp_shift = tmp[shift_cnt:]
    for i in range(shift_cnt):
        tmp_shift += '0'

    return reverse_bytes(bin2bytes(tmp_shift))

def combine_byte_array(msb, lsb):
    tmp = b''
    tmp += lsb
    tmp += msb

    return tmp


def get_ccm_ai(flags, nonce, counter):
    tmp = b''
    tmp += (int(flags)).to_bytes(length=1,byteorder='big',signed=False)
    tmp += nonce
    tmp += counter.to_bytes(length=2,byteorder='big',signed=False)
    return tmp


def get_data_with_offset_and_expand(dataoffset, packet):
    data_array_tmp = b''
    for j in range(16):
        if (dataoffset + j) < len(packet):
            b = packet[dataoffset + j]
        else:
            b = 0
        data_array_tmp += b.to_bytes(length=1, byteorder='big', signed=False)
    return data_array_tmp

def get_data_with_offset_with_limit(dataoffset, packet):
    data_array_tmp = b''
    for j in range(16):
        if (dataoffset + j) < len(packet):
            b = packet[dataoffset + j]
            data_array_tmp += b.to_bytes(length=1, byteorder='big', signed=False)
    return data_array_tmp





def aes_ccm_sub_authentication(M, L, K, N, m, a, debug=False):
    b0 = b''
    a_len = len(a)
    data_len = len(m)
    work_cnt = int((data_len + 15) / 16)

    # flags is define below
    #       Bit Number   Contents
    #       ----------   ----------------------
    #       7            Reserved (always zero)
    #       6            Adata
    #       5 ... 3      M'
    #       2 ... 0      L'
    # M' = (M-2)/2
    # L' = L-1
    # Flags = 64*Adata + 8*M' + L'.
    flags = (a_len>0)*64 + ((M-2)/2)*8 + (L-1)
    # b0 is define below
    #       Octet Number   Contents
    #       ------------   ---------
    #       0              Flags
    #       1 ... 15-L     Nonce N
    #       16-L ... 15    l(m)
    b0 += (int(flags)).to_bytes(length=1,byteorder='big',signed=False)
    b0 += N
    b0 += data_len.to_bytes(length=2,byteorder='big',signed=False)

    if debug: print("CBC IV in[b0]: %s" % (print_hex_little(b0)))
    # X_1 := E( K, B_0 )
    x1 = encrypt(K, b0)
    if debug: print("CBC IV out[x1]: %s" % (print_hex_little(x1)))

    # here only care 0 < l(a) < (2^16 - 2^8)
    # and limit to 16-2.
    #     First two octets   Followed by       Comment
    #     -----------------  ----------------  -------------------------------
    #     0x0000             Nothing           Reserved
    #     0x0001 ... 0xFEFF  Nothing           For 0 < l(a) < (2^16 - 2^8)
    #     0xFF00 ... 0xFFFD  Nothing           Reserved
    #     0xFFFE             4 octets of l(a)  For (2^16 - 2^8) <= l(a) < 2^32
    #     0xFFFF             8 octets of l(a)  For 2^32 <= l(a) < 2^64
    b1 = b''
    b1 += a_len.to_bytes(length=2,byteorder='big',signed=False)
    for i in range(a_len):
        b = a[i]
        b1 += b.to_bytes(length=1,byteorder='big',signed=False)
    # append zero for a.
    for i in range(14 - a_len):
        b = 0
        b1 += b.to_bytes(length=1,byteorder='big',signed=False)

    if debug: print("b1: %s" % (print_hex_little(b1)))
    # X_i + 1 := E(K, X_i XOR B_i ) for i=1, ..., n
    x1_xor_b1 = xor_array(x1, b1)
    if debug: print("After xor: %s [hdr]" % (print_hex_little(x1_xor_b1)))

    x2 = encrypt(K, x1_xor_b1)
    if debug: print("After aes[x2]: %s" % (print_hex_little(x2)))

    # start data process.
    # X_i + 1 := E(K, X_i XOR B_i ) for i=1, ..., n

    xi = x2
    for i in range(work_cnt):
        bi = get_data_with_offset_and_expand(i * 16, m)
        if debug: print("b%s: %s" % (i + 2, print_hex_little(bi)))

        xi_xor_bi = xor_array(xi, bi)
        if debug: print("After xor: %s [msg]" % (print_hex_little(xi_xor_bi)))

        xi_plus_1 = encrypt(K, xi_xor_bi)
        if debug: print("After aes x%s: %s" % (i + 2 + 1, print_hex_little(xi_plus_1)))

        xi = xi_plus_1

    # T := first-M-bytes( X_n+1 )
    T = b''
    for i in range(M):
        b = xi[i]
        T += b.to_bytes(length=1, byteorder='big', signed=False)
    if debug: print("CBC-MAC  [MIC]: %s" % (print_hex_little(T)))

    return T

def aes_ccm_sub_keystream(L, K, N, data_len, debug=False):
    work_cnt = int((data_len + 15) / 16)
    # ctr work start
    # S_i := E( K, A_i ) for i=0, 1, 2, ...
    #    The Flags field is formatted as follows:
    #
    #       Bit Number   Contents
    #       ----------   ----------------------
    #       7            Reserved (always zero)
    #       6            Reserved (always zero)
    #       5 ... 3      Zero
    #       2 ... 0      L'
    flags = L-1

    # A_i is define below
    #       Octet Number   Contents
    #       ------------   ---------
    #       0              Flags
    #       1 ... 15-L     Nonce N
    #       16-L ... 15    Counter i
    s_array = []
    
    for counter in range(work_cnt + 1):
        ai = get_ccm_ai(flags, N, counter)
        si = encrypt(K, ai)

        s_array.append(si)

        if counter == 1:
            if debug: print("CTR Start: %s" % (print_hex_little(ai)))
        if counter > 0:
            if debug: print("CTR [%s], s%s: %s" % (counter, counter, print_hex_little(si)))

    return s_array

def aes_ccm_sub_ctr_xor(s_array, data, debug=False):
    data_xor = b''
    for counter in range(len(s_array) - 1):
        si = s_array[counter + 1]

        sub_data = get_data_with_offset_with_limit((counter) * 16, data)
        data_xor += xor_array(sub_data, si)
    
    return data_xor

def aes_ccm_sub_ctr(M, L, K, N, m, debug=False):
    data_len = len(m)
    # ctr work start
    # S_i := E( K, A_i ) for i=0, 1, 2, ...
    s_array = aes_ccm_sub_keystream(L, K, N, data_len, debug)

    c = aes_ccm_sub_ctr_xor(s_array, m, debug)

    s0 = s_array[0]
    s0_sub_mac = b''
    for i in range(M):
        b = s0[i]
        s0_sub_mac += b.to_bytes(length=1, byteorder='big', signed=False)
    if debug: print("CTR[MAC ]: %s" % (print_hex_little(s0_sub_mac)))

    return c, s0_sub_mac



# Name  Description                               Size    Encoding
# ----  ----------------------------------------  ------  --------
# M     Number of octets in authentication field  3 bits  (M-2)/2
# L     Number of octets in length field          3 bits  L-1

# Name  Description                          Size
# ----  -----------------------------------  -----------------------
# K     Block cipher key                     Depends on block cipher
# N     Nonce                                15-L octets
# m     Message to authenticate and encrypt  l(m) octets
# a     Additional authenticated data        l(a) octets
def aes_ccm_encrypt(M, L, K, N, m, a, debug=False):
    if debug: print("M: %s" % (M))
    if debug: print("L: %s" % (L))
    if debug: print("K: %s" % (print_hex_little(K)))
    if debug: print("N: %s" % (print_hex_little(N)))
    if debug: print("m: %s" % (print_hex_little(m)))
    if debug: print("a: %s" % (print_hex_little(a)))
    
    # 2.2.  Authentication
    T = aes_ccm_sub_authentication(M, L, K, N, m, a, debug)

    # 2.3.  Encryption
    c, s0_sub_mac = aes_ccm_sub_ctr(M, L, K, N, m, debug)

    # U := T XOR first-M-bytes( S_0 )
    U = xor_array(T, s0_sub_mac)

    data_enc = b''
    # first a bytes is un-enc
    data_enc += a
    # second c bytes is enc
    data_enc += c
    # last U bytes is MIC
    data_enc += U

    return data_enc




# Name  Description                               Size    Encoding
# ----  ----------------------------------------  ------  --------
# M     Number of octets in authentication field  3 bits  (M-2)/2
# L     Number of octets in length field          3 bits  L-1

# Name  Description                          Size
# ----  -----------------------------------  -----------------------
# K     Block cipher key                     Depends on block cipher
# N     Nonce                                15-L octets
# c     Encrypt Message                      l(m) octets
# a     Additional authenticated data        l(a) octets
# U_in  Authenticate In                      M octets
def aes_ccm_decrypt(M, L, K, N, c, a, U_in, debug=False):
    if debug: print("M: %s" % (M))
    if debug: print("L: %s" % (L))
    if debug: print("K: %s" % (print_hex_little(K)))
    if debug: print("N: %s" % (print_hex_little(N)))
    if debug: print("c: %s" % (print_hex_little(c)))
    if debug: print("a: %s" % (print_hex_little(a)))
    if debug: print("U_in: %s" % (print_hex_little(U_in)))

    # 2.3.  Decryption
    m, s0_sub_mac = aes_ccm_sub_ctr(M, L, K, N, c, debug)

    # 2.2.  Authentication
    T = aes_ccm_sub_authentication(M, L, K, N, m, a, debug)

    # U := T XOR first-M-bytes( S_0 )
    U = xor_array(T, s0_sub_mac)

    assert(U == U_in)

    return a + m

def aes_ccm_encrypt_packet(M, L, K, N, a_len, packet_with_add, debug=False):
    a = packet_with_add[0 : a_len]

    data_real_len = len(packet_with_add) - a_len
    m = packet_with_add[a_len : a_len + data_real_len]

    return aes_ccm_encrypt(M, L, K, N, m, a, debug)

def aes_ccm_decrypt_packet(M, L, K, N, a_len, packet_with_add, debug=False):
    a = packet_with_add[0 : a_len]

    data_real_len = len(packet_with_add) - a_len - M
    c = packet_with_add[a_len : a_len + data_real_len]
    
    U_in = packet_with_add[-M : ]
    return aes_ccm_decrypt(M, L, K, N, c, a, U_in, debug)


def aes_ccm_packet_header_to_a(header):
    # NESN, SN, MD set 0.
    return (header & 0xe3).to_bytes(length=1, byteorder='big', signed=False)

def aes_ccm_encrypt_bluetooth(M, L, K, IV, packetCounter, directionBit, header, payload, debug=False):
    N = b''
    N += (packetCounter & 0x7ffffffff | (directionBit << 39)).to_bytes(length=5, byteorder='little', signed=False)
    N += reverse_bytes(IV) 
    
    a = aes_ccm_packet_header_to_a(header)
    m = payload

    return aes_ccm_encrypt(M, L, K, N, m, a, debug)







def print_hex_little(arr):
    return arr.hex()

def print_hex_big(arr):
    return "0x" + reverse_bytes(arr).hex()


def smp_e(key, plaintextData, debug=False):
    if debug: print("--- smp_e start ---")
    if debug: print("key: ", print_hex_big(key))
    if debug: print("plaintextData: ", print_hex_big(plaintextData))
    key = reverse_bytes(key)
    plaintextData = reverse_bytes(plaintextData)
    encryptedData = reverse_bytes(encrypt(key, plaintextData))  # 加密
    if debug: print("encryptedData: ", print_hex_big(encryptedData))
    if debug: print("--- smp_e end ---")

    return encryptedData


# Random address hash function ah.
# k is 128 bits
# r is 24 bits
# padding is 104 bits
def smp_ah(k, r):
    print("k: %s" % (print_hex_big(k)))
    print("r: %s" % (print_hex_big(r)))
    padding = bytes.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00')
    # r’ = padding || r
    r = combine_byte_array(padding, r)
    print("r': %s" % (print_hex_big(r)))
    # ah(k, r) = e(k, r’) mod 2^24
    ah = smp_e(k, r)
    print("ah_full: %s" % (print_hex_big(ah)))
    ah = ah[0:3]
    print("ah: %s" % (print_hex_big(ah)))

    return ah



# Confirm value generation function c1 for LE legacy pairing
# k is 128 bits
# r is 128 bits
# pres is 56 bits
# preq is 56 bits
# iat is 1 bit
# ia is 48 bits
# rat is 1 bit
# ra is 48 bits
# padding is 32 zero bits
def smp_c1(k, r, pres, preq, iat, ia, rat, ra):
    print("k: %s" % (print_hex_big(k)))
    print("r: %s" % (print_hex_big(r)))
    print("pres: %s" % (print_hex_big(pres)))
    print("preq: %s" % (print_hex_big(preq)))
    print("iat: %s" % (print_hex_big(iat)))
    print("ia: %s" % (print_hex_big(ia)))
    print("rat: %s" % (print_hex_big(rat)))
    print("ra: %s" % (print_hex_big(ra)))
    # iat is concatenated with 7 zero bits to create iat’ which is 8 bits in length. iat is the least significant bit of iat’.
    # rat is concatenated with 7 zero bits to create rat’ which is 8 bits in length. rat is the least significant bit of rat’.
    # p1 = pres || preq || rat’ || iat’
    p1 = combine_byte_array(combine_byte_array(combine_byte_array(pres, preq), rat), iat)
    print("p1: %s" % (print_hex_big(p1)))
    padding = bytes.fromhex('00 00 00 00')
    # p2 = padding || ia || ra
    p2 = combine_byte_array(combine_byte_array(padding, ia), ra)
    print("p2: %s" % (print_hex_big(p2)))
    # c1 (k, r, preq, pres, iat, rat, ia, ra) = e(k, e(k, r XOR p1) XOR p2)
    c1 = smp_e(k, xor_array(smp_e(k, xor_array(r, p1)), p2))
    print("c1: %s" % (print_hex_big(c1)))

    return c1



# Key generation function s1 for LE legacy pairing
# k is 128 bits
# r1 is 128 bits
# r2 is 128 bits
def smp_s1(k, r1, r2):
    print("k: %s" % (print_hex_big(k)))
    print("r1: %s" % (print_hex_big(r1)))
    print("r2: %s" % (print_hex_big(r2)))
    # The most significant 64-bits of r1 are discarded to generate r1’ 
    # and the most significant 64-bits of r2 are discarded to generate r2’.
    # r’ = r1’ || r2’
    r = combine_byte_array(r1[0:8], r2[0:8])
    print("r': %s" % (print_hex_big(r)))
    # s1(k, r1, r2) = e(k, r’)
    s1 = smp_e(k, r)
    print("s1: %s" % (print_hex_big(s1)))

    return s1





def smp_cmac_msb(info):
    return info[-1] & 0x80 != 0

def smp_cmac_padding(arr):
    length = len(arr)
    pad = b''

    reserve_size = 16 - length
    for j in range(reserve_size):
        if j == reserve_size - 1:
            pad += 0x80.to_bytes(length=1,byteorder='big',signed=False)
        else:
            pad += 0x00.to_bytes(length=1,byteorder='big',signed=False)
    
    return combine_byte_array(arr, pad)

#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#    +                    Algorithm Generate_Subkey                      +
#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#    +                                                                   +
#    +   Input    : K (128-bit key)                                      +
#    +   Output   : K1 (128-bit first subkey)                            +
#    +              K2 (128-bit second subkey)                           +
#    +-------------------------------------------------------------------+
#    +                                                                   +
#    +   Constants: const_Zero is 0x00000000000000000000000000000000     +
#    +              const_Rb   is 0x00000000000000000000000000000087     +
#    +   Variables: L          for output of AES-128 applied to 0^128    +
#    +                                                                   +
#    +   Step 1.  L := AES-128(K, const_Zero);                           +
#    +   Step 2.  if MSB(L) is equal to 0                                +
#    +            then    K1 := L << 1;                                  +
#    +            else    K1 := (L << 1) XOR const_Rb;                   +
#    +   Step 3.  if MSB(K1) is equal to 0                               +
#    +            then    K2 := K1 << 1;                                 +
#    +            else    K2 := (K1 << 1) XOR const_Rb;                  +
#    +   Step 4.  return K1, K2;                                         +
#    +                                                                   +
#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
def smp_aes_cmac_generate_subkey(K, debug=False):
    if debug: print("K: %s" % (print_hex_big(K)))
    const_Zero = get_bytes_from_big_eddian_string('00000000000000000000000000000000')
    const_Rb = get_bytes_from_big_eddian_string('00000000000000000000000000000087')

    L = smp_e(K, const_Zero)
    if debug: print("L: %s" % (print_hex_big(L)))

    if smp_cmac_msb(L) == 0:
        K1 = lshift_array(L, 1)
    else:
        K1 = xor_array(lshift_array(L, 1), const_Rb)
    
    if smp_cmac_msb(K1) == 0:
        K2 = lshift_array(K1, 1)
    else:
        K2 = xor_array(lshift_array(K1, 1), const_Rb)

    if debug: print("K1: %s" % (print_hex_big(K1)))
    if debug: print("K2: %s" % (print_hex_big(K2)))

    return K1, K2


#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#    +                   Algorithm AES-CMAC                              +
#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#    +                                                                   +
#    +   Input    : K    ( 128-bit key )                                 +
#    +            : M    ( message to be authenticated )                 +
#    +            : len  ( length of the message in octets )             +
#    +   Output   : T    ( message authentication code )                 +
#    +                                                                   +
#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#    +   Constants: const_Zero is 0x00000000000000000000000000000000     +
#    +              const_Bsize is 16                                    +
#    +                                                                   +
#    +   Variables: K1, K2 for 128-bit subkeys                           +
#    +              M_i is the i-th block (i=1..ceil(len/const_Bsize))   +
#    +              M_last is the last block xor-ed with K1 or K2        +
#    +              n      for number of blocks to be processed          +
#    +              r      for number of octets of last block            +
#    +              flag   for denoting if last block is complete or not +
#    +                                                                   +
#    +   Step 1.  (K1,K2) := Generate_Subkey(K);                         +
#    +   Step 2.  n := ceil(len/const_Bsize);                            +
#    +   Step 3.  if n = 0                                               +
#    +            then                                                   +
#    +                 n := 1;                                           +
#    +                 flag := false;                                    +
#    +            else                                                   +
#    +                 if len mod const_Bsize is 0                       +
#    +                 then flag := true;                                +
#    +                 else flag := false;                               +
#    +                                                                   +
#    +   Step 4.  if flag is true                                        +
#    +            then M_last := M_n XOR K1;                             +
#    +            else M_last := padding(M_n) XOR K2;                    +
#    +   Step 5.  X := const_Zero;                                       +
#    +   Step 6.  for i := 1 to n-1 do                                   +
#    +                begin                                              +
#    +                  Y := X XOR M_i;                                  +
#    +                  X := AES-128(K,Y);                               +
#    +                end                                                +
#    +            Y := M_last XOR X;                                     +
#    +            T := AES-128(K,Y);                                     +
#    +   Step 7.  return T;                                              +
#    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
def smp_aes_cmac(K, M, debug=False):
    m_len = len(M)
    if debug: print("K: %s" % (print_hex_big(K)))
    if debug: print("M: %s" % (print_hex_big(M)))
    if debug: print("len: %s" % m_len)

    const_Zero = get_bytes_from_big_eddian_string('00000000000000000000000000000000')
    const_Bsize = 16

    K1, K2 = smp_aes_cmac_generate_subkey(K, debug)

    n = math.ceil(m_len/const_Bsize)
    if debug: print("n: %s" % n)

    if n == 0:
        n = 1
        flag = False
    else:
        if m_len % const_Bsize == 0:
            flag = True
        else:
            flag = False
    if debug: print("flag: %s" % flag)
    if debug: print("n: %s" % n)
    
    M_n = reverse_bytes(get_data_with_offset_with_limit((n - 1) * 16, reverse_bytes(M)))
    if debug: print("M_n: %s" % (print_hex_big(M_n)))
    if flag:
        M_last = xor_array(M_n, K1)
    else:
        M_n_padding = smp_cmac_padding(M_n)
        if debug: print("M_n_padding: %s" % (print_hex_big(M_n_padding)))
        M_last = xor_array(M_n_padding, K2)
    #if debug: print("M_n: %s" % (print_hex_big(M_n)))
    if debug: print("M_last: %s" % (print_hex_big(M_last)))
    
    X = const_Zero

    for i in range(n - 1):
        M_i = reverse_bytes(get_data_with_offset_and_expand(i * 16, reverse_bytes(M)))
        Y = xor_array(X, M_i)
        X = smp_e(K, Y)

        if debug: print("i: %s" % i)
        if debug: print("M_i: %s" % (print_hex_big(M_i)))
        if debug: print("Y: %s" % (print_hex_big(Y)))
        if debug: print("X: %s" % (print_hex_big(X)))

    Y = xor_array(M_last, X)
    T = smp_e(K, Y)

    if debug: print("Y: %s" % (print_hex_big(Y)))
    if debug: print("T: %s" % (print_hex_big(T)))

    return T


# LE Secure Connections confirm value generation function f4
# U is 256 bits
# V is 256 bits
# X is 128 bits
# Z is 8 bits
def smp_f4(U, V, X, Z):
    print("U: %s" % (print_hex_big(U)))
    print("V: %s" % (print_hex_big(V)))
    print("X: %s" % (print_hex_big(X)))
    print("Z: %s" % (print_hex_big(Z)))
    # The least significant octet of Z becomes the least significant octet of the AESCMAC
    # input message m and the most significant octet of U becomes the most
    # significant octet of the AES-CMAC input message m.
    # f4(U, V, X, Z) = AES-CMACX (U || V || Z)
    m = combine_byte_array(combine_byte_array(U, V), Z)
    print("m: %s" % (print_hex_big(m)))

    f4 = smp_aes_cmac(X, m)
    print("f4: %s" % (print_hex_big(f4)))

    return f4


# LE Secure Connections key generation function f5
# W is 256 bits
# N1 is 128 bits
# N2 is 128 bits
# A1 is 56 bits
# A2 is 56 bits
def smp_f5(W, N1, N2, A1, A2):
    print("W: %s" % (print_hex_big(W)))
    print("N1: %s" % (print_hex_big(N1)))
    print("N2: %s" % (print_hex_big(N2)))
    print("A1: %s" % (print_hex_big(A1)))
    print("A2: %s" % (print_hex_big(A2)))

    SALT = get_bytes_from_big_eddian_string('6C88 8391 AAF5 A538 6037 0BDB 5A60 83BE')
    keyID = get_bytes_from_big_eddian_string('62746C65')
    # T = AES-CMACSALT (W)
    T = smp_aes_cmac(SALT, W)
    print("T: %s" % (print_hex_big(T)))

    # f5(W, N1, N2, A1, A2) = AES-CMACT (Counter = 0 || keyID || N1 || N2 || A1 ||
    # A2 || Length = 256) || AES-CMACT (Counter = 1 || keyID || N1 || N2 || A1 ||
    # A2 || Length = 256)

    # MacKey || LTK = f5(DHKey, Nc, Np, BD_ADDR_C, BD_ADDR_P)


    # MacKey = AES-CMACT (Counter = 0 || keyID || N1 || N2 || A1 || A2 || Length = 256)
    Counter = get_bytes_from_big_eddian_string('00')
    Length = get_bytes_from_big_eddian_string('01 00')
    m = combine_byte_array(combine_byte_array(combine_byte_array(combine_byte_array(combine_byte_array(combine_byte_array(Counter, keyID), N1), N2), A1), A2), Length)
    MacKey = smp_aes_cmac(T, m)
    print("MacKey: %s" % (print_hex_big(MacKey)))
    
    # LTK = AES-CMACT (Counter = 1 || keyID || N1 || N2 || A1 || A2 || Length = 256)
    Counter = get_bytes_from_big_eddian_string('01')
    Length = get_bytes_from_big_eddian_string('01 00')
    m = combine_byte_array(combine_byte_array(combine_byte_array(combine_byte_array(combine_byte_array(combine_byte_array(Counter, keyID), N1), N2), A1), A2), Length)
    LTK = smp_aes_cmac(T, m)
    print("LTK: %s" % (print_hex_big(LTK)))

    return MacKey, LTK




# LE Secure Connections check value generation function f6
# W is 128 bits
# N1 is 128 bits
# N2 is 128 bits
# R is 128 bits
# IOcap is 24 bits
# A1 is 56 bits
# A2 is 56 bits
def smp_f6(W, N1, N2, R, IOcap, A1, A2):
    print("W: %s" % (print_hex_big(W)))
    print("N1: %s" % (print_hex_big(N1)))
    print("N2: %s" % (print_hex_big(N2)))
    print("R: %s" % (print_hex_big(R)))
    print("IOcap: %s" % (print_hex_big(IOcap)))
    print("A1: %s" % (print_hex_big(A1)))
    print("A2: %s" % (print_hex_big(A2)))

    m = combine_byte_array(combine_byte_array(combine_byte_array(combine_byte_array(combine_byte_array(N1, N2), R), IOcap), A1), A2)
    print("m: %s" % (print_hex_big(m)))

    # f6(W, N1, N2, R, IOcap, A1, A2) = AES-CMACW (N1 || N2 || R || IOcap || A1 || A2)
    f6 = smp_aes_cmac(W, m)
    print("f6: %s" % (print_hex_big(f6)))

    return f6




# LE Secure Connections numeric comparison value generation function g2
# U is 256 bits
# V is 256 bits
# X is 128 bits
# Y is 128 bits
def smp_g2(U, V, X, Y):
    print("U: %s" % (print_hex_big(U)))
    print("V: %s" % (print_hex_big(V)))
    print("X: %s" % (print_hex_big(X)))
    print("Y: %s" % (print_hex_big(Y)))
    # g2(U, V, X, Y) = AES-CMACX(U || V || Y) mod 232
    m = combine_byte_array(combine_byte_array(U, V), Y)
    print("m: %s" % (print_hex_big(m)))

    g2 = smp_aes_cmac(X, m)[0:4]
    print("g2: %s" % (print_hex_big(g2)))

    return g2




# Link key conversion function h6
# W is 128 bits
# keyID is 32 bits
def smp_h6(W, keyID):
    print("W: %s" % (print_hex_big(W)))
    print("keyID: %s" % (print_hex_big(keyID)))

    # h6(W, keyID) = AES-CMACW(keyID)
    h6 = smp_aes_cmac(W, keyID)
    print("h6: %s" % (print_hex_big(h6)))

    return h6


# Link key conversion function h7
# SALT is 32 bits
# W is 128 bits
def smp_h7(SALT, W):
    print("SALT: %s" % (print_hex_big(SALT)))
    print("W: %s" % (print_hex_big(W)))

    # h7(SALT, W) = AES-CMACSALT(W)
    h7 = smp_aes_cmac(SALT, W)
    print("h7: %s" % (print_hex_big(h7)))

    return h7































def print_header(str):
    split_line = "###################################################################################"
    print(split_line)
    split_line_size = len(split_line)
    str_size = len(str)

    start_pos = int(split_line_size/2 - str_size/2)
    header_str = ''
    for i in range(split_line_size):
        if i == 0 or i == split_line_size - 1:
            header_str += '#'
        elif i >= start_pos and i < (start_pos + str_size):
            header_str += str[i - start_pos]
        else:
            header_str += ' '
    print(header_str)
    print(split_line)

def print_result_with_exp(result):
    result_str = "Error"
    if result:
        result_str = "Pass"
    print(">>>>>>>>>> %s <<<<<<<<<<" % result_str)

    assert(result)


def aes_ecb_test():
    print_header("aes_ecb_test")

    key = bytes.fromhex("00000000000000000000000000000000")
    plain_text = bytes.fromhex("112233445566778899AABBCCDDEEFF00")

    e = encrypt(key, plain_text)  # 加密
    print("key:", key.hex())
    print("plain_text:", plain_text.hex())
    print("e:", e.hex())
    d = decrypt(key, e)  # 解密
    print("d:", d.hex())
    print_result_with_exp(d == plain_text)


def smp_ah_test():
    print_header("smp_ah_test")
    print_header("D.7 ah RANDOM ADDRESS HASH FUNCTIONS")
    # IRK ec0234a3 57c8ad05 341010a6 0a397d9b
    # prand 00000000 00000000 00000000 00708194
    # M 00000000 00000000 00000000 00708194
    # AES_128 159d5fb7 2ebe2311 a48c1bdc c40dfbaa
    # ah 0dfbaa
    k = get_bytes_from_big_eddian_string('ec0234a3 57c8ad05 341010a6 0a397d9b')
    r = get_bytes_from_big_eddian_string('708194')
    ah = smp_ah(k, r)

    ah_exp = get_bytes_from_big_eddian_string('0dfbaa')
    print_result_with_exp(ah == ah_exp)


def smp_c1_test():
    print_header("smp_c1_test")
    k = get_bytes_from_big_eddian_string('00000000000000000000000000000000')
    r = get_bytes_from_big_eddian_string('5783D52156AD6F0E6388274EC6702EE0')
    pres = get_bytes_from_big_eddian_string('05000800000302')
    preq = get_bytes_from_big_eddian_string('07071000000101')
    iat = get_bytes_from_big_eddian_string('01')
    ia = get_bytes_from_big_eddian_string('A1A2A3A4A5A6')
    rat = get_bytes_from_big_eddian_string('00')
    ra = get_bytes_from_big_eddian_string('B1B2B3B4B5B6')
    c1 = smp_c1(k, r, pres, preq, iat, ia, rat, ra)

    c1_exp = get_bytes_from_big_eddian_string('1E1E3FEF878988EAD2A74DC5BEF13B86')
    print_result_with_exp(c1 == c1_exp)

def smp_s1_test():
    print_header("smp_s1_test")
    k = get_bytes_from_big_eddian_string('00000000000000000000000000000000')
    r1 = get_bytes_from_big_eddian_string('000F0E0D0C0B0A091122334455667788')
    r2 = get_bytes_from_big_eddian_string('010203040506070899AABBCCDDEEFF00')
    s1 = smp_s1(k, r1, r2)

    s1_exp = get_bytes_from_big_eddian_string('9a1fe1f0e8b0f49b5b4216ae796da062')
    print_result_with_exp(s1 == s1_exp)



def smp_aes_cmac_test():
    print_header("smp_aes_cmac_test")

    print_header("D.1 AES-CMAC RFC4493 TEST VECTORS")
    K = get_bytes_from_big_eddian_string('2b7e1516 28aed2a6 abf71588 09cf4f3c')
    K1, K2 = smp_aes_cmac_generate_subkey(K, True)

    K1_exp = get_bytes_from_big_eddian_string('fbeed618 35713366 7c85e08f 7236a8de')
    K2_exp = get_bytes_from_big_eddian_string('f7ddac30 6ae266cc f90bc11e e46d513b')
    print_result_with_exp(K1 == K1_exp)
    print_result_with_exp(K2 == K2_exp)

    print_header("D.1.1 Example 1: Len = 0")
    M = get_bytes_from_big_eddian_string('')
    aes_cmac = smp_aes_cmac(K, M, True)
    
    aes_cmac_exp = get_bytes_from_big_eddian_string('bb1d6929 e9593728 7fa37d12 9b756746')
    print_result_with_exp(aes_cmac == aes_cmac_exp)

    print_header("D.1.2 Example 2: Len = 16")
    M = get_bytes_from_big_eddian_string('6bc1bee2 2e409f96 e93d7e11 7393172a')
    aes_cmac = smp_aes_cmac(K, M, True)
    
    aes_cmac_exp = get_bytes_from_big_eddian_string('070a16b4 6b4d4144 f79bdd9d d04a287c')
    print_result_with_exp(aes_cmac == aes_cmac_exp)

    print_header("D.1.3 Example 3: Len = 40")
    M = get_bytes_from_big_eddian_string('6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 30c81c46 a35ce411')
    aes_cmac = smp_aes_cmac(K, M, True)
    
    aes_cmac_exp = get_bytes_from_big_eddian_string('dfa66747 de9ae630 30ca3261 1497c827')
    print_result_with_exp(aes_cmac == aes_cmac_exp)


    print_header("D.1.4 Example 4: Len = 64")
    M = get_bytes_from_big_eddian_string('6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710')
    aes_cmac = smp_aes_cmac(K, M, True)
    
    aes_cmac_exp = get_bytes_from_big_eddian_string('51f0bebf 7e3b9d92 fc497417 79363cfe')
    print_result_with_exp(aes_cmac == aes_cmac_exp)



def smp_f4_test():
    print_header("smp_f4_test")
    print_header("D.2 f4 LE SC CONFIRM VALUE GENERATION FUNCTION")
    U = get_bytes_from_big_eddian_string('20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6')
    V = get_bytes_from_big_eddian_string('55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd')
    X = get_bytes_from_big_eddian_string('d5cb8454 d177733e ffffb2ec 712baeab')
    Z = get_bytes_from_big_eddian_string('00')

    f4 = smp_f4(U, V, X, Z)

    f4_exp = get_bytes_from_big_eddian_string('f2c916f1 07a9bd1c f1eda1be a974872d')
    print_result_with_exp(f4 == f4_exp)



def smp_f5_test():
    print_header("smp_f5_test")
    print_header("D.3 f5 LE SC KEY GENERATION FUNCTION")
    W = get_bytes_from_big_eddian_string('ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698')
    N1 = get_bytes_from_big_eddian_string('d5cb8454 d177733e ffffb2ec 712baeab')
    N2 = get_bytes_from_big_eddian_string('a6e8e7cc 25a75f6e 216583f7 ff3dc4cf')
    A1 = get_bytes_from_big_eddian_string('00561237 37bfce')
    A2 = get_bytes_from_big_eddian_string('00a71370 2dcfc1')

    MacKey, LTK = smp_f5(W, N1, N2, A1, A2)

    MacKey_exp = get_bytes_from_big_eddian_string('2965f176 a1084a02 fd3f6a20 ce636e20')
    print_result_with_exp(MacKey == MacKey_exp)
    LTK_exp = get_bytes_from_big_eddian_string('69867911 69d7cd23 980522b5 94750a38')
    print_result_with_exp(LTK == LTK_exp)


def smp_f6_test():
    print_header("smp_f6_test")
    print_header("D.4 f6 LE SC CHECK VALUE GENERATION FUNCTION")
    W = get_bytes_from_big_eddian_string('2965f176 a1084a02 fd3f6a20 ce636e20')
    N1 = get_bytes_from_big_eddian_string('d5cb8454 d177733e ffffb2ec 712baeab')
    N2 = get_bytes_from_big_eddian_string('a6e8e7cc 25a75f6e 216583f7 ff3dc4cf')
    
    R = get_bytes_from_big_eddian_string('12a3343b b453bb54 08da42d2 0c2d0fc8')
    IOcap = get_bytes_from_big_eddian_string('010102')

    A1 = get_bytes_from_big_eddian_string('00561237 37bfce')
    A2 = get_bytes_from_big_eddian_string('00a71370 2dcfc1')

    f6 = smp_f6(W, N1, N2, R, IOcap, A1, A2)

    f6_exp = get_bytes_from_big_eddian_string('e3c47398 9cd0e8c5 d26c0b09 da958f61')
    print_result_with_exp(f6 == f6_exp)



def smp_g2_test():
    print_header("smp_g2_test")
    print_header("D.5 g2 LE SC NUMERIC COMPARISON GENERATION FUNCTION")
    U = get_bytes_from_big_eddian_string('20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6')
    V = get_bytes_from_big_eddian_string('55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd')
    X = get_bytes_from_big_eddian_string('d5cb8454 d177733e ffffb2ec 712baeab')
    Y = get_bytes_from_big_eddian_string('a6e8e7cc 25a75f6e 216583f7 ff3dc4cf')

    g2 = smp_g2(U, V, X, Y)

    # Compare Value = g2 (U, V, X, Y) mod 106
    Compare_Value = int(print_hex_big(g2), 16) % 1000000
    print("Compare_Value: %s" % (Compare_Value))

    g2_exp = get_bytes_from_big_eddian_string('2f9ed5ba')
    print_result_with_exp(g2 == g2_exp)




def smp_h6_test():
    print_header("smp_h6_test")
    print_header("D.6 h6 LE SC LINK KEY CONVERSION FUNCTION")
    W = get_bytes_from_big_eddian_string('ec0234a3 57c8ad05 341010a6 0a397d9b')
    keyID = get_bytes_from_big_eddian_string('6c656272')

    h6 = smp_h6(W, keyID)

    h6_exp = get_bytes_from_big_eddian_string('2d9ae102 e76dc91c e8d3a9e2 80b16399')
    print_result_with_exp(h6 == h6_exp)



def smp_h7_test():
    print_header("smp_h7_test")
    print_header("D.8 h7 LE SC LINK KEY CONVERSION FUNCTION")
    SALT = get_bytes_from_big_eddian_string('00000000 00000000 00000000 746D7031')
    W = get_bytes_from_big_eddian_string('ec0234a3 57c8ad05 341010a6 0a397d9b')

    h7 = smp_h6(SALT, W)

    h7_exp = get_bytes_from_big_eddian_string('fb173597 c6a3c0ec d2998c2a 75a57011')
    print_result_with_exp(h7 == h7_exp)







def encrypt_ccm_rfc3610_test():
    # ccm test
    # =============== Packet Vector #1 ==================
    print_header("encrypt_ccm_rfc3610_test")
    M = 8
    L = 2
    a_len = 8

    print_header("Packet Vector #1")
    K = bytes.fromhex('C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF')
    N = bytes.fromhex('00 00 00 03  02 01 00 A0  A1 A2 A3 A4  A5')
    packet = bytes.fromhex("00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F 10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E")
    packet_enc = aes_ccm_encrypt_packet(M, L, K, N, a_len, packet, True)
    packet_enc_exp = bytes.fromhex('00 01 02 03  04 05 06 07  58 8C 97 9A  61 C6 63 D2 F0 66 D0 C2  C0 F9 89 80  6D 5F 6B 61  DA C3 84 17 E8 D1 2C FD  F9 26 E0')
    print_result_with_exp(packet_enc == packet_enc_exp)
    # decrypt check
    packet_dec = aes_ccm_decrypt_packet(M, L, K, N, a_len, packet_enc, True)
    print_result_with_exp(packet == packet_dec)


    print_header("Packet Vector #2")
    K = bytes.fromhex('C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF')
    N = bytes.fromhex('00 00 00 04  03 02 01 A0  A1 A2 A3 A4  A5')
    packet = bytes.fromhex("00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F 10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F")
    packet_enc = aes_ccm_encrypt_packet(M, L, K, N, a_len, packet, True)
    packet_enc_exp = bytes.fromhex('00 01 02 03  04 05 06 07  72 C9 1A 36  E1 35 F8 CF 29 1C A8 94  08 5C 87 E3  CC 15 C4 39  C9 E4 3A 3B A0 91 D5 6E  10 40 09 16')
    print_result_with_exp(packet_enc == packet_enc_exp)
    # decrypt check
    packet_dec = aes_ccm_decrypt_packet(M, L, K, N, a_len, packet_enc, True)
    print_result_with_exp(packet == packet_dec)

    print_header("Packet Vector #3")
    K = bytes.fromhex('C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF')
    N = bytes.fromhex('00 00 00 05  04 03 02 A0  A1 A2 A3 A4  A5')
    packet = bytes.fromhex("00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F 10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F 20")
    packet_enc = aes_ccm_encrypt_packet(M, L, K, N, a_len, packet, True)
    packet_enc_exp = bytes.fromhex('00 01 02 03  04 05 06 07  51 B1 E5 F4  4A 19 7D 1D A4 6B 0F 8E  2D 28 2A E8  71 E8 38 BB  64 DA 85 96 57 4A DA A7  6F BD 9F B0  C5')
    print_result_with_exp(packet_enc == packet_enc_exp)
    # decrypt check
    packet_dec = aes_ccm_decrypt_packet(M, L, K, N, a_len, packet_enc, True)
    print_result_with_exp(packet == packet_dec)


def encrypt_ccm_bt_test():
    print_header("encrypt_ccm_bt_test")

    M = 4
    L = 2

    SK = bytes.fromhex("99AD1B5226A37E3E058E3B8E27C2C666")
    IV = bytes.fromhex("DEAFBABEBADCAB24")
    
    print_header("1.START_ENC_RSP1 (packet 0, Central → Peripheral)")
    packetCounter = 0
    directionBit = 1

    header = 0x0f
    payload = bytes.fromhex("06")
    packet_enc = aes_ccm_encrypt_bluetooth(M, L, SK, IV, packetCounter, directionBit, header, payload, True)
    packet_enc_exp = aes_ccm_packet_header_to_a(header) + bytes.fromhex('9f cd a7 f4 48')
    print_result_with_exp(packet_enc == packet_enc_exp)


    
    print_header("2.START_ENC_RSP2 (packet 0, Peripheral → Central)")
    packetCounter = 0
    directionBit = 0

    header = 0x07
    payload = bytes.fromhex("06")
    packet_enc = aes_ccm_encrypt_bluetooth(M, L, SK, IV, packetCounter, directionBit, header, payload, True)
    packet_enc_exp = aes_ccm_packet_header_to_a(header) + bytes.fromhex('a3 4c 13 a4 15')
    print_result_with_exp(packet_enc == packet_enc_exp)


    print_header("3. Data packet1 (packet 1, Central → Peripheral)")
    packetCounter = 1
    directionBit = 1

    header = 0x0E
    payload = bytes.fromhex("17 00 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 31 32 33 34 35 36 37 38 39 30")
    packet_enc = aes_ccm_encrypt_bluetooth(M, L, SK, IV, packetCounter, directionBit, header, payload, True)
    packet_enc_exp = aes_ccm_packet_header_to_a(header) + bytes.fromhex('7A 70 D6 64 15 22 6D F2 6B 17 83 9A 06 04 05 59 6B D6 56 4F 79 6B 5B 9C E6 FF 32 F7 5A 6D 33')
    print_result_with_exp(packet_enc == packet_enc_exp)


    print_header("4. Data packet2 (packet 1, Peripheral → Central)")
    packetCounter = 1
    directionBit = 0

    header = 0x06
    payload = bytes.fromhex("17 00 37 36 35 34 33 32 31 30 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51")
    packet_enc = aes_ccm_encrypt_bluetooth(M, L, SK, IV, packetCounter, directionBit, header, payload, True)
    packet_enc_exp = aes_ccm_packet_header_to_a(header) + bytes.fromhex('F3 88 81 E7 BD 94 C9 C3 69 B9 A6 68 46 DD 47 86 AA 8C 39 CE 54 0D 0D AE 3A DC DF 89 B9 60 88')
    print_result_with_exp(packet_enc == packet_enc_exp)






















# P-192, Spec5.3-Page 992
ECC_P192 = EllipticCurve(
    p=6277101735386680763835789423207666416083908700390324961279,
    a=-3,
    b=0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
    g=(0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012, 
        0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811),
    n=6277101735386680763835789423176059013767194773182842284081,
)

# P-256, Spec5.3-Page 992
ECC_P256 = EllipticCurve(
    p=115792089210356248762697446949407573530086143415290314195533631308867097853951,
    a=-3,
    b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    g=(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
    n=115792089210356248762697446949407573529996955224135760342422259061068512044369,
)

def ecc_P192_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, DHKey):
    # Check public key in curve
    print_result_with_exp(curve.is_on_curve((PublicAx, PublicAy)))
    
    # Check public key
    CalAx, CalAy = curve.mult(PrivateA, curve.g)
    print("Calulate PublicA: (0x%x, 0x%x)" % (CalAx, CalAy))
    print_result_with_exp(CalAx == PublicAx)
    print_result_with_exp(CalAy == PublicAy)

    # Check DHKey By (PrivateB * PublicA)
    CalDHKeyx, CalDHKeyy = curve.mult(PrivateB, (PublicAx, PublicAy))
    print("Calulate(PrivateB * PublicA) DHKey: (0x%x, 0x%x)" % (CalDHKeyx, CalDHKeyy))
    print_result_with_exp(CalDHKeyx == DHKey)

    # Check DHKey By (PrivateA * PrivateB * G)
    CalDHKeyx, CalDHKeyy = curve.mult(PrivateA * PrivateB, curve.g)
    print("Calulate(PrivateA * PrivateB * G) DHKey: (0x%x, 0x%x)" % (CalDHKeyx, CalDHKeyy))
    print_result_with_exp(CalDHKeyx == DHKey)


def ecc_P192_test():
    print_header("ecc_P192_test")
    print_header("7.1.1.1 P-192 data set 1")
    curve = ECC_P192

    PrivateA = 0x07915f86918ddc27005df1d6cf0c142b625ed2eff4a518ff
    PrivateB = 0x1e636ca790b50f68f15d8dbe86244e309211d635de00e16d
    PublicAx = 0x15207009984421a6586f9fc3fe7e4329d2809ea51125f8ed
    PublicAy = 0xb09d42b81bc5bd009f79e4b59dbbaa857fca856fb9f7ea25
    DHKey = 0xfb3ba2012c7e62466e486e229290175b4afebc13fdccee46
    ecc_P192_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, DHKey)
    
    print_header("7.1.1.2 P-192 data set 2")
    PrivateA = 0x52ec1ca6e0ec973c29065c3ca10be80057243002f09bb43e
    PrivateB = 0x57231203533e9efe18cc622fd0e34c6a29c6e0fa3ab3bc53
    PublicAx = 0x45571f027e0d690795d61560804da5de789a48f94ab4b07e
    PublicAy = 0x0220016e8a6bce74b45ffec1e664aaa0273b7cbd907a8e2b
    DHKey = 0xa20a34b5497332aa7a76ab135cc0c168333be309d463c0c0
    ecc_P192_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, DHKey)
    
    print_header("7.1.1.3 P-192 data set 3")
    PrivateA = 0x00a0df08eaf51e6e7be519d67c6749ea3f4517cdd2e9e821
    PrivateB = 0x2bf5e0d1699d50ca5025e8e2d9b13244b4d322a328be1821
    PublicAx = 0x2ed35b430fa45f9d329186d754eeeb0495f0f653127f613d
    PublicAy = 0x27e08db74e424395052ddae7e3d5a8fecb52a8039b735b73
    DHKey = 0x3b3986ba70790762f282a12a6d3bcae7a2ca01e25b87724e
    ecc_P192_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, DHKey)

    
    print_header("7.1.1.4 P-192 data set 4")
    PrivateA = 0x030a4af66e1a4d590a83e0284fca5cdf83292b84f4c71168
    PrivateB = 0x12448b5c69ecd10c0471060f2bf86345c5e83c03d16bae2c
    PublicAx = 0xf24a6899218fa912e7e4a8ba9357cb8182958f9fa42c968c
    PublicAy = 0x7c0b8a9ebe6ea92e968c3a65f9f1a9716fe826ad88c97032
    DHKey = 0x4a78f83fba757c35f94abea43e92effdd2bc700723c61939
    ecc_P192_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, DHKey)

    
    print_header("7.1.1.5 P-192 data set 5")
    PrivateA = 0x604df406c649cb460be16244589a40895c0db7367dc11a2f
    PrivateB = 0x526c2327303cd505b9cf0c012471902bb9e842ce32b0addc
    PublicAx = 0xcbe3c629aceb41b73d475a79fbfe8c08cdc80ceec00ee7c9
    PublicAy = 0xf9f70f7ae42abda4f33af56f7f6aa383354e453fa1a2bd18
    DHKey = 0x64d4fe35567e6ea0ca31f947e1533a635436d4870ce88c45
    ecc_P192_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, DHKey)

    
    print_header("7.1.1.6 P-192 data set 6")
    PrivateA = 0x1a2c582a09852979eb2cee18fb0befb9a55a6d06f6a8fad3
    PrivateB = 0x243778916920d68df535955bc1a3cccd5811133a8205ae41
    PublicAx = 0xeca2d8d30bbef3ba8b7d591fdb98064a6c7b870cdcebe67c
    PublicAy = 0x2e4163a44f3ae26e70dae86f1bf786e1a5db5562a8ed9fee
    DHKey = 0x6433b36a7e9341940e78a63e31b3cf023282f7f1e3bf83bd
    ecc_P192_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, DHKey)

    
    print_header("7.1.1.7 P-192 data set 7")
    PrivateA = 0x0f494dd08b493edb07228058a9f30797ff147a5a2adef9b3
    PrivateB = 0x2da4cd46d9e06e81b1542503f2da89372e927877becec1be
    PublicAx = 0x9f56a8aa27346d66652a546abacc7d69c17fd66e0853989f
    PublicAy = 0xd7234c1464882250df7bbe67e0fa22aae475dc58af0c4210
    DHKey = 0xc67beda9baf3c96a30616bf87a7d0ae704bc969e5cad354b
    ecc_P192_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, DHKey)

    
    print_header("7.1.1.8 P-192 data set 8")
    PrivateA = 0x7381d2bc6ddecb65126564cb1af6ca1985d19fb57f0fff16
    PrivateB = 0x18e276beff75adc3d520badb3806822e1c820f1064447848
    PublicAx = 0x61c7f3c6f9e09f41423dce889de1973d346f2505a5a3b19b
    PublicAy = 0x919972ff4cd6aed8a4821e3adc358b41f7be07ede20137df
    DHKey = 0x6931496eef2fcfb03e0b1eef515dd4e1b0115b8b241b0b84
    ecc_P192_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, DHKey)

    
    print_header("7.1.1.9 P-192 data set 9")
    PrivateA = 0x41c7b484ddc37ef6b7952c379f87593789dac6e4f3d8d8e6
    PrivateB = 0x33e4eaa77f78216e0e99a9b200f81d2ca20dc74ad62d9b78
    PublicAx = 0x9f09c773adb8e7b66b5d986cd15b143341a66d824113c15f
    PublicAy = 0xd2000a91738217ab8070a76c5f96c03de317dfab774f4837
    DHKey = 0xa518f3826bb5fa3d5bc37da4217296d5b6af51e5445c6625
    ecc_P192_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, DHKey)

    
    print_header("7.1.1.10 P-192 data set 10")
    PrivateA = 0x703cf5ee9c075f7726d0bb36d131c664f5534a6e6305d631
    PrivateB = 0x757291c620a0e7e9dd13ce09ceb729c0ce1980e64d569b5f
    PublicAx = 0xfa2b96d382cf894aeeb0bd985f3891e655a6315cd5060d03
    PublicAy = 0xf7e8206d05c7255300cc56c88448158c497f2df596add7a2
    DHKey = 0x12a3343bb453bb5408da42d20c2d0fcc18ff078f56d9c68c
    ecc_P192_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, DHKey)



def ecc_P256_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, PublicBx, PublicBy, DHKey):
    # Check public key in curve
    print_result_with_exp(curve.is_on_curve((PublicAx, PublicAy)))
    
    # Check public key
    CalAx, CalAy = curve.mult(PrivateA, curve.g)
    print("Calulate PublicA: (0x%x, 0x%x)" % (CalAx, CalAy))
    print_result_with_exp(CalAx == PublicAx)
    print_result_with_exp(CalAy == PublicAy)
    
    # Check public key in curve
    print_result_with_exp(curve.is_on_curve((PublicBx, PublicBy)))
    
    # Check public key
    CalBx, CalBy = curve.mult(PrivateB, curve.g)
    print("Calulate PublicB: (0x%x, 0x%x)" % (CalBx, CalBy))
    print_result_with_exp(CalBx == PublicBx)
    print_result_with_exp(CalBy == PublicBy)

    # Check DHKey By (PrivateB * PublicA)
    CalDHKeyx, CalDHKeyy = curve.mult(PrivateB, (PublicAx, PublicAy))
    print("Calulate(PrivateB * PublicA) DHKey: (0x%x, 0x%x)" % (CalDHKeyx, CalDHKeyy))
    print_result_with_exp(CalDHKeyx == DHKey)

    # Check DHKey By (PrivateA * PublicB)
    CalDHKeyx, CalDHKeyy = curve.mult(PrivateA, (PublicBx, PublicBy))
    print("Calulate(PrivateA * PublicB) DHKey: (0x%x, 0x%x)" % (CalDHKeyx, CalDHKeyy))
    print_result_with_exp(CalDHKeyx == DHKey)

    # Check DHKey By (PrivateA * PrivateB * G)
    CalDHKeyx, CalDHKeyy = curve.mult(PrivateA * PrivateB, curve.g)
    print("Calulate(PrivateA * PrivateB * G) DHKey: (0x%x, 0x%x)" % (CalDHKeyx, CalDHKeyy))
    print_result_with_exp(CalDHKeyx == DHKey)

def ecc_P256_test():
    print_header("ecc_P256_test")
    print_header("7.1.2 P-256 sample data")
    curve = ECC_P256

    print_header("7.1.2.1 P-256 data set 1")
    PrivateA = 0x3f49f6d4a3c55f3874c9b3e3d2103f504aff607beb40b7995899b8a6cd3c1abd
    PrivateB = 0x55188b3d32f6bb9a900afcfbeed4e72a59cb9ac2f19d7cfb6b4fdd49f47fc5fd
    PublicAx = 0x20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de6
    PublicAy = 0xdc809c49652aeb6d63329abf5a52155c766345c28fed3024741c8ed01589d28b
    PublicBx = 0x1ea1f0f01faf1d9609592284f19e4c0047b58afd8615a69f559077b22faaa190
    PublicBy = 0x4c55f33e429dad377356703a9ab85160472d1130e28e36765f89aff915b1214a
    DHKey = 0xec0234a357c8ad05341010a60a397d9b99796b13b4f866f1868d34f373bfa698
    ecc_P256_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, PublicBx, PublicBy, DHKey)


    print_header("7.1.2.2 P-256 data set 2")
    PrivateA = 0x06a516693c9aa31a6084545d0c5db641b48572b97203ddffb7ac73f7d0457663
    PrivateB = 0x529aa0670d72cd6497502ed473502b037e8803b5c60829a5a3caa219505530ba
    PublicAx = 0x2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd
    PublicAy = 0x919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4f
    PublicBx = 0xf465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc
    PublicBy = 0x0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279
    DHKey = 0xab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69
    ecc_P256_check(curve, PrivateA, PrivateB, PublicAx, PublicAy, PublicBx, PublicBy, DHKey)




if __name__ == '__main__':
    # aes ecb
    aes_ecb_test()

    # le legacy encrypt
    smp_ah_test()
    smp_c1_test()
    smp_s1_test()

    # le secure connection
    smp_aes_cmac_test()
    smp_f4_test()
    smp_f5_test()
    smp_f6_test()
    smp_g2_test()
    smp_h6_test()
    smp_h7_test()

    # Link Layer Security test
    encrypt_ccm_rfc3610_test()
    encrypt_ccm_bt_test()

    # ECC test
    ecc_P192_test()
    ecc_P256_test()


    