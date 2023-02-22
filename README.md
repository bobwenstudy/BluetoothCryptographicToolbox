# 概述

在蓝牙LE Spec中，有一个很重要的概念就是加密，加密分为SMP和链路层加密（Link Layer Security），其实就是为了安全考虑的各种加密和秘钥生成方法。为了解决中间人攻击，监听，安全的问题，Spec定义的一堆加密函数及其使用方法。

其中SMP主要实现链路层link key和其他key的生成和分发功能，而链路层加密确保对空口数据的进行加密，防止被交互数据被监听。

在芯片具体实现中，经常会听同事说一些是需要硬件支持，那为什么一定要硬件支持呢，软件难道不能做吗，软件做的局限性在哪？那要确定这些问题，那就必须了解各个加密算法实现原理，才能进一步分析清楚软硬件之间的差异。

为了研究这一问题，最简单的办法就是将所有相关算法实现一遍，并了解各个算法的作用范围。为更好的分析其算法实现，本文采用python作为开发语言，对各个加密算法原理和其具体实现具体进行说明。

项目测试代码地址：https://github.com/bobwenstudy/BluetoothCryptographicToolbox.git

# 加密算法实现

## 算法分布

在LE实现加密总共有两大块内容，分别是SMP和Link Layer Security，这两个模块分别用到不同的加密算法，其分布如下。

![image-20230220095038348](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230220095038348.png)

在SMP中，分为**Legacy Encrypt**和**Secure Connection**，其中**Legacy Encrypt**使用的加密算法是**AES-128**。Secure Connection使用的加密算法包括**AES-CMAC**和**Elliptic Curve P-256**算法。

Link Layer Security使用的是**AES-CCM**算法。

## 算法分类

按照对称加密和非对称加密可以将上述加密算法分为两类。

对称加密包括**AES-128**、**AES-CMAC**和**AES-CCM**。其中**AES-CMAC**和**AES-CCM**这两个是**AES-128**的变种，只是用法不同。

非对称加密为**Elliptic Curve P-256**。

![image-20230220095712849](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230220095712849.png)



## AES-128算法

### 原理概述

在Core Spec v5.4 P1550中有定义LE加密所使用的加密算法为[NIST Publication FIPS-197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)，网上也有很多介绍AES-128是什么的说明文档（[python实现AES-128](https://blog.csdn.net/qq_46123866/article/details/125057391)），这个东西还是比较好理解的，主要就是一堆的矩阵运算，作为软件工程师，只需要知道输入输出即可。

在蓝牙中将其定义为**e**，相应函数如下，输入为128位的**key（秘钥）**和128位**plaintextData（明文）**，输出是一个128位的**encryptedData（密文）**。

![image-20230220141150575](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230220141150575.png)

如下图所示，引用自：[AES加密的详细过程是怎么样的？ - 知乎 (zhihu.com)](https://www.zhihu.com/question/27307070)。其中K是**key（秘钥）**，D是**plaintextData（明文）**，C是**encryptedData（密文）**。详细的加密流程可以看引用的文档。

图左侧（蓝色）部分是对明文的处理。**首先**，D_i是一个明文byte（=8bit），一共有16个D_i，也就是下方4X4的矩阵，这个矩阵被称为**state**，换算过来就是16x8=128bits（就是AES一个block的大小）。**其次**，每一个**round（轮函数）**就是一套数据操作，简单理解为“加、减、乘、除”，而每一个**round**的输入是上一个**round**的输出，换言之，最初**state**是明文，**round**目的就是不停修改**state**内容。

图右侧（红色）部分是对密钥的处理。**首先**，K_i是一个密钥byte（=8bit），对图中AES-128（也就是密钥长度128bit的加密算法，平时我们常接触到的是就是AES-128）一共有16个K_i（AES-192就是24个，AES-256是32个）。密钥的结构和**state**相似，也是16x8=128bits，和block大小相同，被称为**roundkey（轮密）**。**其次**，每一个**round（轮函数）**结束后，**roundkey**也会被修改，对应的修改算法/过程被称为密钥扩展算法**（Key Expansion/Schedule）**。

![v2-1624dadf04878abf6a32a7062e145fc5_r](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/v2-1624dadf04878abf6a32a7062e145fc5_r.jpg)

**注意**，在AES-128中还有很多类似ECB，CBC等概念，这些就是基于AES-128的使用方法，这些和后面所介绍的**AES-CMAC**和**AES-CCM**类似。都是其变种用法。

**注意**，这里的计算都在32位之内，整数计算，用C语言实现还是很方便的。

### 算法实现

知道了AES-128的原理后，使用也比较简单，python有很多对应的实现库，这里用**Crypto.Cipher**库中**AES**模块。模式选择ECB模式，确保输入的明文长度和秘钥长度都是128位，输出的加密数据就是128位。

加密使用encrypt函数，解密使用decrypt函数，即可实现数据的加解密工作。

```python
from Crypto.Cipher import AES

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
```



设计小的测试代码来验证其功能：

```python
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
```



输出结果如下。可以看到加密后的数据**e**和原本的key还有plain_text基本没相似度，但是通过解密后的**d**和明文相同，测试通过。

```
###################################################################################
#                                  aes_ecb_test                                   #
###################################################################################
key: 00000000000000000000000000000000
plain_text: 112233445566778899aabbccddeeff00
e: 9a1fe1f0e8b0f49b5b4216ae796da062
d: 112233445566778899aabbccddeeff00
>>>>>>>>>> Pass <<<<<<<<<<
```





## AES-CMAC算法

### 原理概述

在Core Spec v5.4 P1553中有定义SMP在Secure Connection下所需的加密算法，[RFC4993](https://www.ietf.org/rfc/rfc4493.txt)，网上也有很多介绍AES-CMAC的文章[AES-CMAC加密算法使用](https://blog.csdn.net/weixin_46018097/article/details/113793423)，全称是Cipher-based Message Authentication Code (CMAC)。主要就是一堆的AES运算，作为软件工程师，只需要知道输入输出即可。

在蓝牙中将其定义为**AES-CMAC**，相应函数如下，输入为128位的**k（秘钥）**和要验证的可变长度的数据**m（信息）**，输出是一个128位的**MAC（信息验证码）**。

![image-20230220141448731](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230220141448731.png)

算法的工作示意图如下所示，这个东西还是比较好理解的，就是将**m（信息）**拆分成一系列128bit的数据，和**k（秘钥）**进行AES-128计算，前一个计算结果和消息载荷进行+运算，再进行AES-128运算，最后一个信息片段根据是否满足128bit选择和K1或者K2进行+运算，不足128bit的部分补10^i。最后得到的T就是MAC值。

![image-20230220141005588](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230220141005588.png)





### 算法实现

知道了AES-CMAC的原理后，本质就是AES-128的变种使用，直接实现相应的封装函数，多次调用AES-128运算即可。

按照其算法说明，设计并实现`smp_aes_cmac()`函数，输入秘钥**K**和消息**m**，输出128bit的MAC值。先调用`smp_aes_cmac_generate_subkey()`函数生成**K1**和**K2**，而后将M拆分为多个128bit序列，进行多次AES-128运算，最终生成MAC。

```python
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
```



参考[RFC4993](https://www.ietf.org/rfc/rfc4493.txt)里面的例程（Core Spec v5.4 P1641中的case也一样），设计小的测试代码来验证其功能，需要注意的是，例程中的数据时大端的，需要调用`get_bytes_from_big_eddian_string()`函数转换为小端：

```python
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
```



输出结果如下，测试数据在文档。

```
###################################################################################
#                                smp_aes_cmac_test                                #
###################################################################################
###################################################################################
#                        D.1 AES-CMAC RFC4493 TEST VECTORS                        #
###################################################################################
K: 0x2b7e151628aed2a6abf7158809cf4f3c
L: 0x7df76b0c1ab899b33e42f047b91b546f
K1: 0xfbeed618357133667c85e08f7236a8de
K2: 0xf7ddac306ae266ccf90bc11ee46d513b
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                            D.1.1 Example 1: Len = 0                             #
###################################################################################
K: 0x2b7e151628aed2a6abf7158809cf4f3c
M: 0x
len: 0
K: 0x2b7e151628aed2a6abf7158809cf4f3c
L: 0x7df76b0c1ab899b33e42f047b91b546f
K1: 0xfbeed618357133667c85e08f7236a8de
K2: 0xf7ddac306ae266ccf90bc11ee46d513b
n: 0
flag: False
n: 1
M_n: 0x
M_n_padding: 0x80000000000000000000000000000000
M_last: 0x77ddac306ae266ccf90bc11ee46d513b
Y: 0x77ddac306ae266ccf90bc11ee46d513b
T: 0xbb1d6929e95937287fa37d129b756746
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                            D.1.2 Example 2: Len = 16                            #
###################################################################################
K: 0x2b7e151628aed2a6abf7158809cf4f3c
M: 0x6bc1bee22e409f96e93d7e117393172a
len: 16
K: 0x2b7e151628aed2a6abf7158809cf4f3c
L: 0x7df76b0c1ab899b33e42f047b91b546f
K1: 0xfbeed618357133667c85e08f7236a8de
K2: 0xf7ddac306ae266ccf90bc11ee46d513b
n: 1
flag: True
n: 1
M_n: 0x6bc1bee22e409f96e93d7e117393172a
M_last: 0x902f68fa1b31acf095b89e9e01a5bff4
Y: 0x902f68fa1b31acf095b89e9e01a5bff4
T: 0x070a16b46b4d4144f79bdd9dd04a287c
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                            D.1.3 Example 3: Len = 40                            #
###################################################################################
K: 0x2b7e151628aed2a6abf7158809cf4f3c
M: 0x6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411
len: 40
K: 0x2b7e151628aed2a6abf7158809cf4f3c
L: 0x7df76b0c1ab899b33e42f047b91b546f
K1: 0xfbeed618357133667c85e08f7236a8de
K2: 0xf7ddac306ae266ccf90bc11ee46d513b
n: 3
flag: False
n: 3
M_n: 0x30c81c46a35ce411
M_n_padding: 0x30c81c46a35ce4118000000000000000
M_last: 0xc715b076c9be82dd790bc11ee46d513b
i: 0
M_i: 0x6bc1bee22e409f96e93d7e117393172a
Y: 0x6bc1bee22e409f96e93d7e117393172a
X: 0x3ad77bb40d7a3660a89ecaf32466ef97
i: 1
M_i: 0xae2d8a571e03ac9c9eb76fac45af8e51
Y: 0x94faf1e313799afc3629a55f61c961c6
X: 0xb148c17f309ee692287ae57cf12add49
Y: 0x765d7109f920644f5171246215478c72
T: 0xdfa66747de9ae63030ca32611497c827
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                            D.1.4 Example 4: Len = 64                            #
###################################################################################
K: 0x2b7e151628aed2a6abf7158809cf4f3c
M: 0x6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
len: 64
K: 0x2b7e151628aed2a6abf7158809cf4f3c
L: 0x7df76b0c1ab899b33e42f047b91b546f
K1: 0xfbeed618357133667c85e08f7236a8de
K2: 0xf7ddac306ae266ccf90bc11ee46d513b
n: 4
flag: True
n: 4
M_n: 0xf69f2445df4f9b17ad2b417be66c3710
M_last: 0x0d71f25dea3ea871d1aea1f4945a9fce
i: 0
M_i: 0x6bc1bee22e409f96e93d7e117393172a
Y: 0x6bc1bee22e409f96e93d7e117393172a
X: 0x3ad77bb40d7a3660a89ecaf32466ef97
i: 1
M_i: 0xae2d8a571e03ac9c9eb76fac45af8e51
Y: 0x94faf1e313799afc3629a55f61c961c6
X: 0xb148c17f309ee692287ae57cf12add49
i: 2
M_i: 0x30c81c46a35ce411e5fbc1191a0a52ef
Y: 0x8180dd3993c20283cd812465eb208fa6
X: 0xc93d11bfaf08c5dc4d90b37b4dee002b
Y: 0xc44ce3e245366dad9c3e128fd9b49fe5
T: 0x51f0bebf7e3b9d92fc49741779363cfe
>>>>>>>>>> Pass <<<<<<<<<<
```



## AES-CCM算法

### 原理概述

在Core Spec v5.4 P3038中有定义LE Link Layer Security所使用的加密算法为AES-CCM，说明在：[RFC3610](https://www.ietf.org/rfc/rfc3610.txt)，和AES-CMAC类似，是基于AES-128的变种，用法有些不同，作为软件工程师，只需要知道输入输出即可。

该算法用于空口数据的加解密流程，也就是发送方对数据加密，接收方对数据解密，总体交互示意图如下所示。

发送方和接收方公用参数K、M、L和N；

发送方将a和m经过AES-CCM加密后，生成a+c+U的带认证的数据包发送给接收方；

接收方将收到的数据包进行AES-CCM解密，将c还原为m，并对U进行验证，确保消息的完整性。

![image-20230221120545519](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221120545519.png)

#### 输入参数

该算法的输入有6个参数，分别如下。

![image-20230220193215545](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230220193215545.png)

![image-20230220193230202](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230220193230202.png)



#### 认证

AES-CCM算法除了对数据载荷进行加解密运算外，还需要对数据进行完整性校验，在数据包末尾附加长度为M的校验信息。

所以算法的第一步是用**CBC-MAC [MAC]**计算认证信息**T**。

总体示意图如下。

![image-20230221111548346](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221111548346.png)

- **Step1**：生成数组B_0, B_1, ..., B_n

其中**B_0**为16字节，其组成如下。

![image-20230221101844040](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221101844040.png)

Flags组成如下，也可以直接`Flags = 64*Adata + 8*M' + L'`这样计算。

![image-20230221102519957](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221102519957.png)

在**B_0**之后开始添加附加信息**a**，生成的**B_i**拼接在**B_0**之后。其组成规则如下：

![image-20230221104035659](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221104035659.png)

目前我们只考虑**a**长度为`0 < l(a) < (2^16 - 2^8)`场景，特殊点，当`0 < l(a) < 16-2`时，这时附加信息生成`B_1`，其组成如下：

![image-20230221104710035](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221104710035.png)

在附加信息**a**之后，就是用消息**m**生成之后的**B_i**，将**m**拆分为16字节的字节序列作为**B_i**，最后不足16字节部分补0。总个数为`(l(m) + 15) / 16`。

- **Step2**：CBC-MAC计算

按照下面公式依次计算，生成**X_i**，取**X_n+1**的前**M**个字节就是所需的**T**。

![image-20230221111257406](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221111257406.png)





#### 加密

为了确保数据交互的安全性，需要对数据进行加密，加密采用Counter(CTR)模式来计算。上述完成了数据的认证信息**T**的计算，本节对信息m进行加密，生成加密信息**c**和最终消息完整性校验值**U**。

总体操作示意图如下：

![image-20230221114659896](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221114659896.png)

- **Step1**：生成keystream S_i := E( K, A_i )   for i=0, 1, 2, ...

要生成S_i，需要先生成**A_i**，其组成如下，Counter总个数为`(l(m) + 15) / 16`。：

![image-20230221112343570](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221112343570.png)

Flags的组成如下，也可以直接`Flags = L'`这样计算。

![image-20230221112452006](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221112452006.png)

- **Step2**：xor运算

而后用生成**S_i**和消息**m**，按照16字节块进行**xor**运算，最终生成加密信息**c**。



- **Step3**：生成校验信息**U**

![image-20230221114238375](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221114238375.png)

最终输出数据为`a || c1…cn || U`，由三部分组成，开始是**l(a)**长度的输入数据a，和输入的**a**相同，中间是l(m)长度的**m**加密后的数据**c**，尾部是长度为**M**的消息校验，总长度为**l(a)+l(m)+M**。

![image-20230221092801153](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221092801153.png)





#### 解密

接收方收到带校验信息的数据包后，需要对加密后的数据**c**进行解密还原数据**m**，并对信息完整性**U**进行二次校验。依然采用Counter(CTR)模式来计算，只是最后的xor运算输入为**c**，输出为**m**。

总体操作示意图如下：

![image-20230221114803944](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221114803944.png)









### 蓝牙参数配置说明

从上述描述中，可以看出，AES-CCM需要很多参数，在Core Spec v5.4 P3041中有定义了蓝牙如何使用AES-CCM进行数据加密的配置。

#### M参数

M=4，也就是MIC长度为4字节。

#### L参数

L=2，长度信息为2字节，虽然LE的包最大长度为1字节，但是预留1个字节以备用。

#### K参数

**HCI_LE_Enable_Encryption** Command中的Long_Term_Key

**HCI_LE_Long_Term_Key_Request_Reply** Command中的Long_Term_Key

#### N参数

由**IV**，**packetCounter**和**directionBit**三个变量共同组成。

- **IV**：Data Physical Channel下，由**LL_ENC_REQ**中的**IV_C**和**LL_ENC_RSP**中的**IV_P**拼接而成，共8字节。
- **packetCounter**，Data Physical Channel下，每次加密开始后，第一笔数据包packetCounter为0，之后每加密一笔新数据包就+1，重传不影响该变量。
- **directionBit**，Data Physical Channel下，从Central发起为1，从Peripheral发起为0。



![image-20230221183633922](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221183633922.png)

#### m参数

PDU的Payload部分。

#### a参数

PDU的第一个字节，根据不同通道，选择的bit位置0，其他未选中bit位保留。

- **Data Physical channel PDU**: NESN, SN, MD.
- **Connected Isochronous PDU**: NESN, SN, NPI, CIE.
- **Broadcast Isochronous PDU**: CSSN, CSTF.





### 算法实现

按照算法原理，对算法进行实现。

`aes_ccm_sub_authentication()`，函数实现**CBC-MAC [MAC]**计算认证信息**T**流程。

`aes_ccm_sub_ctr()`，函数实现加密/解密的CTR流程流程，最终生成**c/m**和**s0_sub_mac**。里面包含`aes_ccm_sub_keystream()`流程生成**S_i**序列，和`aes_ccm_sub_ctr_xor()`进行xor运算最终生成**c/m**。

`aes_ccm_encrypt()`，AES-CCM加密封装函数，先调用`aes_ccm_sub_authentication()`计算认证信息**T**，而后调用`aes_ccm_sub_ctr()`流程生成**c**和**s0_sub_mac**，而后将数据包拼接，最终输出带校验信息的加密的数据包`a || c1…cn || U`。

`aes_ccm_decrypt()`，AES-CCM解密封装函数，先调用`aes_ccm_sub_ctr()`流程生成**m**和**s0_sub_mac**，而后将生成的**m**调用`aes_ccm_sub_authentication()`计算认证信息**T**，而后比较输入**U_in**和计算所得**U**是否匹配，最终输出解密后的数据包`a || m`。

```python

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

    if U != U_in: assert("Error MIC")

    return a + m
```



#### rfc3610例程测试

参考[RFC3610](https://www.ietf.org/rfc/rfc3610.txt)里面的例程，设计小的测试代码来验证其功能，需要注意的是，例程中的数据是小端的：

```python
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
```



生成结果如下，和文档里描述的计算过程匹配：

```
###################################################################################
#                            encrypt_ccm_rfc3610_test                             #
###################################################################################
###################################################################################
#                                Packet Vector #1                                 #
###################################################################################
M: 8
L: 2
K: c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
N: 00000003020100a0a1a2a3a4a5
m: 08090a0b0c0d0e0f101112131415161718191a1b1c1d1e
a: 0001020304050607
CBC IV in[b0]: 5900000003020100a0a1a2a3a4a50017
CBC IV out[x1]: eb9d5547730955ab231e0a2dfe4b90d6
b1: 00080001020304050607000000000000
After xor: eb955546710a51ae25190a2dfe4b90d6 [hdr]
After aes[x2]: cdb6411e3cdc9b4f5d9258b69ee7f091
b2: 08090a0b0c0d0e0f1011121314151617
After xor: c5bf4b1530d195404d834aa58af2e686 [msg]
After aes x3: 9c38405ea03c1bc904b58b40c76ca2eb
b3: 18191a1b1c1d1e000000000000000000
After xor: 84215a45bc2105c904b58b40c76ca2eb [msg]
After aes x4: 2dc697e411ca83a860c2c406ccaa542f
CBC-MAC  [MIC]: 2dc697e411ca83a8
CTR Start: 0100000003020100a0a1a2a3a4a50001
CTR [1], s1: 50859d916dcb6ddde077c2d1d4ec9f97
CTR [2], s2: 7546717ac6de9aff640c9c06de6d0d8f
CTR[MAC ]: 3a2e46c8ec33a548
>>>>>>>>>> Pass <<<<<<<<<<
M: 8
L: 2
K: c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
N: 00000003020100a0a1a2a3a4a5
c: 588c979a61c663d2f066d0c2c0f989806d5f6b61dac384
a: 0001020304050607
U_in: 17e8d12cfdf926e0
CTR Start: 0100000003020100a0a1a2a3a4a50001
CTR [1], s1: 50859d916dcb6ddde077c2d1d4ec9f97
CTR [2], s2: 7546717ac6de9aff640c9c06de6d0d8f
CTR[MAC ]: 3a2e46c8ec33a548
CBC IV in[b0]: 5900000003020100a0a1a2a3a4a50017
CBC IV out[x1]: eb9d5547730955ab231e0a2dfe4b90d6
b1: 00080001020304050607000000000000
After xor: eb955546710a51ae25190a2dfe4b90d6 [hdr]
After aes[x2]: cdb6411e3cdc9b4f5d9258b69ee7f091
b2: 08090a0b0c0d0e0f1011121314151617
After xor: c5bf4b1530d195404d834aa58af2e686 [msg]
After aes x3: 9c38405ea03c1bc904b58b40c76ca2eb
b3: 18191a1b1c1d1e000000000000000000
After xor: 84215a45bc2105c904b58b40c76ca2eb [msg]
After aes x4: 2dc697e411ca83a860c2c406ccaa542f
CBC-MAC  [MIC]: 2dc697e411ca83a8
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                                Packet Vector #2                                 #
###################################################################################
M: 8
L: 2
K: c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
N: 00000004030201a0a1a2a3a4a5
m: 08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
a: 0001020304050607
CBC IV in[b0]: 5900000004030201a0a1a2a3a4a50018
CBC IV out[x1]: f0c254d3ca03e23970bd24a84c399e77
b1: 00080001020304050607000000000000
After xor: f0ca54d2c800e63c76ba24a84c399e77 [hdr]
After aes[x2]: 48de8b8628ea4a4000aa42c295bf4a8c
b2: 08090a0b0c0d0e0f1011121314151617
After xor: 40d7818d24e7444f10bb50d181aa5c9b [msg]
After aes x3: 0f89ffbca62bc24f13215f168796aa33
b3: 18191a1b1c1d1e1f0000000000000000
After xor: 1790e5a7ba36dc5013215f168796aa33 [msg]
After aes x4: f7b9056a86926cf3fb163dc499efaa11
CBC-MAC  [MIC]: f7b9056a86926cf3
CTR Start: 0100000004030201a0a1a2a3a4a50001
CTR [1], s1: 7ac0103ded38f6c0390dba871c4991f4
CTR [2], s2: d40cde22d5f92424f7be9a569da79f51
CTR[MAC ]: 5728d00496d265e5
>>>>>>>>>> Pass <<<<<<<<<<
M: 8
L: 2
K: c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
N: 00000004030201a0a1a2a3a4a5
c: 72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3b
a: 0001020304050607
U_in: a091d56e10400916
CTR Start: 0100000004030201a0a1a2a3a4a50001
CTR [1], s1: 7ac0103ded38f6c0390dba871c4991f4
CTR [2], s2: d40cde22d5f92424f7be9a569da79f51
CTR[MAC ]: 5728d00496d265e5
CBC IV in[b0]: 5900000004030201a0a1a2a3a4a50018
CBC IV out[x1]: f0c254d3ca03e23970bd24a84c399e77
b1: 00080001020304050607000000000000
After xor: f0ca54d2c800e63c76ba24a84c399e77 [hdr]
After aes[x2]: 48de8b8628ea4a4000aa42c295bf4a8c
b2: 08090a0b0c0d0e0f1011121314151617
After xor: 40d7818d24e7444f10bb50d181aa5c9b [msg]
After aes x3: 0f89ffbca62bc24f13215f168796aa33
b3: 18191a1b1c1d1e1f0000000000000000
After xor: 1790e5a7ba36dc5013215f168796aa33 [msg]
After aes x4: f7b9056a86926cf3fb163dc499efaa11
CBC-MAC  [MIC]: f7b9056a86926cf3
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                                Packet Vector #3                                 #
###################################################################################
M: 8
L: 2
K: c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
N: 00000005040302a0a1a2a3a4a5
m: 08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
a: 0001020304050607
CBC IV in[b0]: 5900000005040302a0a1a2a3a4a50019
CBC IV out[x1]: 6f8a12f7bf8d4dc5a1196e95dff0b427
b1: 00080001020304050607000000000000
After xor: 6f8212f6bd8e49c0a71e6e95dff0b427 [hdr]
After aes[x2]: 37e9b78cc22017e73380430cbef42824
b2: 08090a0b0c0d0e0f1011121314151617
After xor: 3fe0bd87ce2d19e82391511faae13e33 [msg]
After aes x3: 90ca05139f4d4ecf226fe981c59e2d40
b3: 18191a1b1c1d1e1f2000000000000000
After xor: 88d31f08835050d0026fe981c59e2d40 [msg]
After aes x4: 73b46775c026deaa410397d670fe5fb0
CBC-MAC  [MIC]: 73b46775c026deaa
CTR Start: 0100000005040302a0a1a2a3a4a50001
CTR [1], s1: 59b8efff46147312b47a1d9d393d3cff
CTR [2], s2: 69f122a078c79b8977894c99975c2378
CTR[MAC ]: 396ec01a7db96e6f
>>>>>>>>>> Pass <<<<<<<<<<
M: 8
L: 2
K: c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
N: 00000005040302a0a1a2a3a4a5
c: 51b1e5f44a197d1da46b0f8e2d282ae871e838bb64da859657
a: 0001020304050607
U_in: 4adaa76fbd9fb0c5
CTR Start: 0100000005040302a0a1a2a3a4a50001
CTR [1], s1: 59b8efff46147312b47a1d9d393d3cff
CTR [2], s2: 69f122a078c79b8977894c99975c2378
CTR[MAC ]: 396ec01a7db96e6f
CBC IV in[b0]: 5900000005040302a0a1a2a3a4a50019
CBC IV out[x1]: 6f8a12f7bf8d4dc5a1196e95dff0b427
b1: 00080001020304050607000000000000
After xor: 6f8212f6bd8e49c0a71e6e95dff0b427 [hdr]
After aes[x2]: 37e9b78cc22017e73380430cbef42824
b2: 08090a0b0c0d0e0f1011121314151617
After xor: 3fe0bd87ce2d19e82391511faae13e33 [msg]
After aes x3: 90ca05139f4d4ecf226fe981c59e2d40
b3: 18191a1b1c1d1e1f2000000000000000
After xor: 88d31f08835050d0026fe981c59e2d40 [msg]
After aes x4: 73b46775c026deaa410397d670fe5fb0
CBC-MAC  [MIC]: 73b46775c026deaa
>>>>>>>>>> Pass <<<<<<<<<<
```



#### 蓝牙例程测试

在Core Spec v5.4 P2918中有部分蓝牙AES的测试case，需要注意的是按照蓝牙参数配置来构建与之匹配的参数。

`aes_ccm_packet_header_to_a()`函数用于将packet header转化为附加信息**a**。

`aes_ccm_encrypt_bluetooth()`函数用于将蓝牙参数转换为AES-CCM所能识别的参数，主要就是拼接参数**N**。

`encrypt_ccm_bt_test()`函数实现case，case有点多，这里共实现了4个case。

```python

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
```





测试结果如下。

```
###################################################################################
#                               encrypt_ccm_bt_test                               #
###################################################################################
###################################################################################
#                1.START_ENC_RSP1 (packet 0, Central → Peripheral)                #
###################################################################################
M: 4
L: 2
K: 99ad1b5226a37e3e058e3b8e27c2c666
N: 000000008024abdcbabebaafde
m: 06
a: 03
CBC IV in[b0]: 49000000008024abdcbabebaafde0001
CBC IV out[x1]: 712eaaaae60603521d245e50786eefe4
b1: 00010300000000000000000000000000
After xor: 712fa9aae60603521d245e50786eefe4 [hdr]
After aes[x2]: debc43782a022675fca0aa6f0854f1ab
b2: 06000000000000000000000000000000
After xor: d8bc43782a022675fca0aa6f0854f1ab [msg]
After aes x3: 6399913fede5fa111bdb993bbfb9be06
CBC-MAC  [MIC]: 6399913f
CTR Start: 01000000008024abdcbabebaafde0001
CTR [1], s1: 99190d88f4aa1b60b97ecfe6f5fee777
CTR[MAC ]: ae3e6577
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                2.START_ENC_RSP2 (packet 0, Peripheral → Central)                #
###################################################################################
M: 4
L: 2
K: 99ad1b5226a37e3e058e3b8e27c2c666
N: 000000000024abdcbabebaafde
m: 06
a: 03
CBC IV in[b0]: 49000000000024abdcbabebaafde0001
CBC IV out[x1]: ddc86e3094f0c29cf341ef4c2c1e0088
b1: 00010300000000000000000000000000
After xor: ddc96d3094f0c29cf341ef4c2c1e0088 [hdr]
After aes[x2]: fe960f5c93fba45a53959842ea8a0c0a
b2: 06000000000000000000000000000000
After xor: f8960f5c93fba45a53959842ea8a0c0a [msg]
After aes x3: db403db3a32f39156faf6a6b472e1010
CBC-MAC  [MIC]: db403db3
CTR Start: 01000000000024abdcbabebaafde0001
CTR [1], s1: a5add4127b2f43788ddc9cd86b0b89d2
CTR[MAC ]: 975399a6
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                3. Data packet1 (packet 1, Central → Peripheral)                 #
###################################################################################
M: 4
L: 2
K: 99ad1b5226a37e3e058e3b8e27c2c666
N: 010000008024abdcbabebaafde
m: 1700636465666768696a6b6c6d6e6f707131323334353637383930
a: 02
CBC IV in[b0]: 49010000008024abdcbabebaafde001b
CBC IV out[x1]: 7c688612996de101f3eacb68b443969c
b1: 00010200000000000000000000000000
After xor: 7c698412996de101f3eacb68b443969c [hdr]
After aes[x2]: e3f1ef5c30161c0a9ec07274a0757fc8
b2: 1700636465666768696a6b6c6d6e6f70
After xor: f4f18c3855707b62f7aa1918cd1b10b8 [msg]
After aes x3: e7e346f5b7c8a6072890a60dcf4ec20a
b3: 71313233343536373839300000000000
After xor: 96d274c683fd903010a9960dcf4ec20a [msg]
After aes x4: 3db113320b182f9fed635db14cac2df0
CBC-MAC  [MIC]: 3db11332
CTR Start: 01010000008024abdcbabebaafde0001
CTR [1], s1: 6d70b50070440a9a027de8f66b6a6a29
CTR [2], s2: 1ae7647c4d5e6dabdec602404c302341
CTR[MAC ]: caeb7e01
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                4. Data packet2 (packet 1, Peripheral → Central)                 #
###################################################################################
M: 4
L: 2
K: 99ad1b5226a37e3e058e3b8e27c2c666
N: 010000000024abdcbabebaafde
m: 170037363534333231304142434445464748494a4b4c4d4e4f5051
a: 02
CBC IV in[b0]: 49010000000024abdcbabebaafde001b
CBC IV out[x1]: 714234d50d6f1da5663be3e78460ad87
b1: 00010200000000000000000000000000
After xor: 714336d50d6f1da5663be3e78460ad87 [hdr]
After aes[x2]: 96df1d97959e6176ac215c7baf90c674
b2: 17003736353433323130414243444546
After xor: 81df2aa1a0aa52449d111d39ecd48332 [msg]
After aes x3: 6cc52c3dcecdc2fa81eb347887960673
b3: 4748494a4b4c4d4e4f50510000000000
After xor: 2b8d657785818fb4cebb657887960673 [msg]
After aes x4: a776a26be617366496c391e36f6374a1
CBC-MAC  [MIC]: a776a26b
CTR Start: 01010000000024abdcbabebaafde0001
CTR [1], s1: e488b6d188a0faf15889e72a059902c0
CTR [2], s2: edc470841f4140e0758c8e8f708399bd
CTR[MAC ]: 2ecfc2e3
>>>>>>>>>> Pass <<<<<<<<<<
```









## Elliptic Curve加密算法

在接触SMP以来，对于这个ECC加密一直很排斥，主要原因就是搞不清楚里面的原理，使用起来也很怪异，尤其是其为什么能实现非对称加密非常好奇，但是其具体实现原理一直没看明白，最近专门学习了下，总算把里面的沟沟道道理解了。

要理解ECC加密，简单点还是先去看RSA，这个好好看看还是能理解的，看明白这个再回头看ECC会清楚些。

### 非对称加密基本概念

在非对称加密中都会有一个秘钥对，公钥和私钥。其中公钥可以分发给任何人，用于对数据加密，私钥用于对数据解密。

从网上找了一个图[什么是非对称加密、公钥、私钥？看这篇就够了！](https://cloud.tencent.com/developer/news/229749)，发送方要发送数据给乙，发送前需要用乙的公钥对数据进行加密，乙收到数据后用私钥对数据进行解密，即可还原甲真实想发的数据。

**注意**，实际蓝牙业务中并不是这样用的，因为非对称加密耗时很长，不可能每笔数据包都用这个算法进行加密，而是用其特性进行LTK的生成，所以看非对称加密的原理归原理，实际使用场景用法并不相同。

![pdp11s84ty](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/pdp11s84ty.jpeg)



### RSA算法

本算法是基于模运算。已知一个整数a，它被整数b除，得到余数c，这很容易。但是反过来，已知b和c，想要求出a，则是不可能的，只能去一个数一个数的去猜。a是私钥，c是公钥。只不过实际的加密算法把这个过程复杂化了。

一些好的文章如下：

[RSA算法原理【超清晰】_JustFlamePlease的博客-CSDN博客_rsa算法原理](https://blog.csdn.net/m0_59363292/article/details/121129579)

[RSA算法原理（一） - 阮一峰的网络日志 (ruanyifeng.com)](http://www.ruanyifeng.com/blog/2013/06/rsa_algorithm_part_one.html)

[RSA算法讲解](https://haokan.baidu.com/v?pd=wisenatural&vid=9787172934671308053)

其基本原理如下图所示（引用：[RSA介绍_chengqiuming的博客-CSDN博客_rsa全称](https://blog.csdn.net/chengqiuming/article/details/82725137)）：

**加密**：RSA的密文是对代表了明文的数字的E次方求mod N的结果。换句话说，就是将明文和自己做E次乘方，然后将其结果除以N求余数，这个余数就是密文。加密公式中出现了两个数——E和N，到底都是什么数呢？RSA的加密是求明文的E次方mod N，因此只要知道E和N这两个数，任何人都可以完成加密的运算。所以说，E和N是RSA加密的密钥，也就是说，E和N的组合就是公钥。

**解密**：该公式表示对密文的数字的D次方求mod N就可以得到明文。换句话说，将密文自己做D次乘法，再对其结果除以N求余数，就可以得到明文。这里使用的数字N和加密时使用的数字N是相同的。数D和数N组成起来就是RSA的解密密钥，因此D和N的组合就是私钥。只有知道D和N两个数的人才能够完成解密的运算。由于N是公钥的一部分，是公开的，因此单独将D称为私钥也是可以的。

![20180916155449615](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/20180916155449615.png)



### Elliptic Curve Cryptography（椭圆曲线加密）

通常我们会搜到类似于**ECC**，**ECDH**，**ECDSA**的东西。**ECC**就是**E**lliptic **C**urve **C**ryptography的缩写，后面是两个DH和DSA在椭圆曲线上面的算法变种。

要理解这个需要看一些资料，非常建议看如下中英文资料：

英文原版：[Elliptic Curve Cryptography: a gentle introduction - Andrea Corbellini](https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/)

翻译的中文版：[椭圆曲线介绍（一）：实数上面的椭圆曲线_AdijeShen的博客-CSDN博客_实数和椭圆曲线转换](https://blog.csdn.net/AdijeShen/article/details/122132389)



下面作为一个软件工程师，来看看这个东西应该怎么理解。

别管他原理是什么，为什么能保证安全什么的，只要记住几个概念：

#### 实数上面的椭圆曲线

##### 椭圆曲线定义

椭圆曲线就是满足下面条件的，曲线上面的所有点构成的一个集合，这种方程形式被叫做维尔斯特拉斯标准形式（Weierstrass normal form）。

![image-20230222092731452](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222092731452.png)



这样的椭圆曲线是与自己相交的，形状上类似：

![e7ebcaf1976a48ad93900d11df337629](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/e7ebcaf1976a48ad93900d11df337629.png)



##### 椭圆曲线群

到这里就有一个**群**的概念，很难理解的东西，别管那么多，记住一些概念就好。

椭圆曲线是具有加法交换群的性质的：

- 群中的元素是椭圆曲线上面的点
- 椭圆曲线的单位元是`0`（定义的无穷远点）
- 一个点`P`的逆元`-P` 就是`P`关于`x`轴对称的那个点
- 加法的定义如下：令`P` , `Q` , `R`是一条直线与椭圆曲线的三个交点，则`P + Q + R = 0 ⟷ Q + R = − P`。

![b4f73d15185a48cf9a3d0901ba800b95](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/b4f73d15185a48cf9a3d0901ba800b95.png)

##### 代数上的加法

知道了椭圆曲线的计算规则，那要如何计算呢？令：

![image-20230221205123959](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221205123959.png)

如果`P` , `Q` 是两个不同点，那么经过他们的直线的斜率为：

![image-20230221205144454](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221205144454.png)

他们与椭圆曲线的交点的坐标为`R`：

![image-20230221205225254](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221205225254.png)

如下图所示是一个计算实例。

![image-20230221205240984](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221205240984.png)

如果`P = Q`，则计算方法为：

![image-20230221205345051](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221205345051.png)

他们与椭圆曲线的交点的坐标为`R`：

![image-20230221205407950](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221205407950.png)

如下图所示是一个计算实例。

![image-20230221205426450](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221205426450.png)



##### 标量乘法

椭圆曲线上没有定义点和点之间的乘法，只有标量乘法，而标量乘法是通过加法来实现的：

![image-20230221205512271](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221205512271.png)

假设add和double的复杂度是`O(1)`的，那么单纯这样的一个标量乘法的复杂度是`O(n)`的，然而却可以通过一些方法来变成`O(log n)` 的。比如`n = 151`的时候，可以把它拆解为`10010111b`，即：

![image-20230221205917186](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221205917186.png)

则计算可以简化为：

![image-20230221205944689](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221205944689.png)

计算过程如下，这样子只需要调用7次double方法和5次add方法。而直接算的话要调用150次add方法。

![image-20230221210035898](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221210035898.png)



##### 对数问题

在**RSA**中，离散对数问题是这样的，令：

![image-20230222092314248](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222092314248.png)

那么通过`( g , h )` 求出`x`是困难的。

而在椭圆曲线上，这样定义对数问题：令`P`属于某个椭圆曲线，

![image-20230222092522981](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222092522981.png)

那个给定`( P , Q )`，求出`n`是困难的。严格意义上来说这种问题应该叫做椭圆曲线上面的除法难题，为了保持一致，也叫做椭圆曲线上的对数难题。





#### 整数域上面的椭圆曲线以及离散对数问题

##### 模p的整数域

其实就是要求x，y都为整数，切公式需要`mod p`，该限定后，y的取值范围必然在`0-p`内。

![image-20230221202635162](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230221202635162.png)

##### 椭圆曲线的阶

有限域上面的椭圆曲线是由有限个点所构成的，那么具体有几个点呢？

首先，定义概念**椭圆曲线群的阶**为当前椭圆曲线群上面的点的数量。

可以直接将x从0到p − 1计数有多少点，但这样的复杂度是`O ( p )`的，在p比较大的时候会很慢，也有比较高效的算法来计算椭圆曲线的阶，比如[Schoof算法](https://en.wikipedia.org/wiki/Schoof's_algorithm)，这里不具体展开。



##### 标量乘法以及循环群

标量乘法的计算方法即为计算多次的加法：

![image-20230222093428572](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222093428572.png)

同样的，可以用之前提出的**二进制分解**的方法来加快运算。

但有限域上面的乘法有一个有趣的性质，就是他会构成一个乘法循环子群。

![cyclic-subgroup](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/cyclic-subgroup.png)

会发现`nP`会在 `(0,P,2P,3P,4P)`这些值中不断循环。可以在[这个链接](https://andrea.corbellini.name/ecc/interactive/modk-mul.html)里面试一下。

![image-20230222093936277](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222093936277.png)

![image-20230222094045749](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222094045749.png)

这样的`P`被称作这个循环子群的**生成元**(generator)或者**基本点**(base point)。

###### 子群的阶

有一个问题就是**由`P`生成的循环子群的阶是多少呢？**。或者换一种说法，`P`的阶是多少？。

- `P`的阶就是令`nP = 0`的最小的n，（0本身除外），在上面的例子里面就是5。
- `P`的阶和整个椭圆曲线的阶是满足[拉格朗日定理](https://en.wikipedia.org/wiki/Lagrange's_theorem_(group_theory))的，也就是说子群的阶可以整除父群的阶。

因此就可以用下面的方法找出某个点P的阶了：

1. 使用[Schoof算法](https://en.wikipedia.org/wiki/Schoof's_algorithm)计算得出整个椭圆曲线的阶N。
2. 找到阶N的所有因子。
3. 对于N的每个因子n，按照从小到大的方式，计算nP。
4. 如果`nP = 0`，那么n是子群的阶。

###### 如何找生成元

在椭圆曲线密码学中，我们需要一个较高次数的子群。所以一般来说，是先取一个曲线，然后计算他的阶N，选择一个比较大的因子n，然后根据这个因子来找到一个合适的生成元。

首先，介绍一下`cofactor`的概念，因拉格朗日定理的存在，所以可以推断`h=N/n`是一个整数，那么这个h就是子群的`cofactor`。

那么对于曲线中的任意一个点，满足`NP = 0`，也可以写成是`n(hP)=0`。

当n为素数时，只要任取一点`P`，令`G=hP`，那么`G`就是一个阶为n的生成元。

![image-20230222094818036](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222094818036.png)



##### 椭圆曲线上面的离散对数问题

在有限域的椭圆曲线中，其离散对数问题定义为：

**如果知道P和Q，那么如何找到一个k使得Q = kP?。**

这样一个问题是一个标准的密码学难题假设，也就是大家公认这个问题是比较困难的。

而那些基于整数群上面的离散对数问题的算法比如DSA或者Diffle-Hellman以及Elgamal，都有其在椭圆曲线上面的平替。

椭圆曲线一个优秀的性质在于，同样对于整数上面的离散对数问题，在参数大小相同的情况下，椭圆曲线的离散对数问题更难解决。

因此，要达到同样的安全等级，椭圆曲线的参数大小更小。



#### 椭圆曲线密码学，ECDH

##### 全局参数

椭圆曲线算法是在有限域内的椭圆曲线中的循环子群上面运行的。因此，需要定义以下这些参数：

- 素数p：定义了有限域的大小
- 参数a和b：椭圆曲线等式的参数
- 生成元G：子群的生成元
- 阶n：子群的阶
- cofactor h：子群的cofactor。nh = N，其中N是整个椭圆曲线的大小（阶）。

总结，全局参数为`(p,a,b,G,n,h)`。



##### 椭圆曲线密码学

基于椭圆曲线的密码学的公私钥基本是如下形式的：

1. **私钥**为一个随机数d，是从`1,...,n-1`当中随机选的，这里n是子群的阶。
2. **公钥**为一个点`H=dG`，这里G是子群的生成元。

可以看到，如果知道私钥d和G，那么计算公钥H是简单的。但如果公钥H和G，那么**计算d是很难的，因为这需要解决一个离散对数问题。**

接下来这里会介绍两个基于椭圆曲线的公钥密码算法：ECDH（Elliptic curve Diffie-Hellman），是一个加密算法。



###### ECDH加密

ECDH是[Diffle-Hellman算法](https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange)的一个变体。其实是一个密钥协商协议。代表着ECDH定义了密钥是如何在两方之间生成并交换。

ECDH具体解决的问题如下：两方（比如[Alice和Bob](http://en.wikipedia.org/wiki/Alice_and_Bob)）想要安全地交换某些信息，使得某个[中间人](http://en.wikipedia.org/wiki/Man-in-the-middle_attack)只能窃听但不能解码得知他们的消息。这也是[TLS](https://baike.baidu.com/item/TLS/2979545)协议的设计宗旨。

具体的步骤如下：

1. 首先，**Alice和Bob生成他们各自的公私钥**。Alice的密钥对：

   ![image-20230222102339592](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222102339592.png)

   Bob的密钥对：

   ![image-20230222102351591](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222102351591.png)

   注意到Alice和Bob公用一套全局参数，比如同一个生成元G GG和同一个椭圆曲线。

2. **Alice和Bob通过安全的信道来交换他们的公钥HA和HB**。中间人可能可以窃听到他们传输的HA和HB的值，但是因为离散对数难题的存在，中间人无法通过公钥计算出dA或dB的值。

3. **Alice和Bob计算各自计算S**，Alice计算的S如下：

   ![image-20230222103010554](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222103010554.png)

   

   Bob计算的S如下：

   ![image-20230222103032458](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222103032458.png)

   注意到两个人算出来的**S**其实是一样的，由此，Alice和Bob就都得到了一个**协商的值S**，而中间人是无法得到的。这里的安全性基于椭圆曲线上的Diffie-Hellman难题。

Diffie-Hellman的密钥协商思想：Alice和Bob都能轻易计算出秘密值，对于中间人来说计算出秘密值是一个困难问题。

![ecdh](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/ecdh.png)



Diffie-Hellman问题的设计宗旨有一个[YouTube视频](https://www.youtube.com/watch?v=YEBfamv-_do#t=02m37s)讲的比较清楚，但他是有限域内的Diffie-Hellman。

椭圆曲线内的Diffie-Hellman难题被公认为是一个“困难问题”，被认为是与离散对数难题一样难解决的，虽然学界还没有形式化的证明说这两个问题一样难。现在可以保证的事情就是Diffle-Hellman问题不会比离散对数难题更加难，因为如果解决了离散对数难题，那么就可以解决Diffle-Hellman问题。

**注意到现在Alice和Bob有了一个共享的秘密值，所以他们就可以使用对称加密来进行数据传输了。**

**注意，蓝牙BLE就是使用ECDH的机制，使用计算出来S的x坐标作为LTK使用。**



#### 椭圆曲线安全性以及P256/P192差异

##### 安全性

从上面的讲述来看，已经对椭圆曲线有一个基本认识。椭圆曲线的安全性的主要基于，令`P`属于某个椭圆曲线，

![image-20230222092522981](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222092522981.png)

那个给定`( P , Q )`，求出`n`是困难的。

那这是为什么呢？

假设用穷举法来分析此问题，由于椭圆曲线是已知的，P和Q也是已知的，简单一点的办法就是穷举了，n的取值范围是由其**子群的阶**决定的。

穷举法的时间复杂度是`O(n)`，当n很小时，不管是记录所有1P,2P,...,nP的数据，还是重新算，都很简单。

但是BLE中采用的是P256算法，在Core Spec v5.4 P993中定义了子群的阶为：

![image-20230222112542485](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222112542485.png)

直接看这个数字可能没什么感觉，假设一次椭圆曲线加密的加法和比较耗时为1us（实际远远大于该值，目前选一个较小的值），那穷举一次的耗时是：

![image-20230222113543491](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222113543491.png)

这个是根本不可能做到的事情，虽然数学上还有一些优化算法，详见[Elliptic Curve Cryptography: breaking security and a comparison with RSA - Andrea Corbellini](https://andrea.corbellini.name/2015/06/08/elliptic-curve-cryptography-breaking-security-and-a-comparison-with-rsa/)，但是依然会是一个异常恐怖的数据量，所以其安全性是可以保证的。

而当用于私钥的一段可以用**二进制分解**的方法来加快运算，计算的时间复杂度为`O(logn)`。对于P256的场景其，可以转化为如下问题：

![image-20230222115113727](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222115113727.png)

所以最大总共225次Double运算和255次Add运算，也就是256次运算，还是很容易计算出来的。



##### P256/P192的差异

其实就是选用的位数不同，P256选的是最大值为2^256，P192最大值为2^192。当然P256的安全性要远高于P192，想靠暴力破解基本是不可能的。

![image-20230222113948607](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222113948607.png)

![image-20230222114008282](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222114008282.png)

![image-20230222114043392](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222114043392.png)

### 算法实现

从上面的说明其实已经对椭圆曲线加密有一定认识了，在python中能直接实现256bit的整数乘除运算，所以无需考虑c语言中大数运算的一系列问题，代码也更直观一些。定义一个`class EllipticCurve`对象来实现对椭圆曲线的管理[代码来源](https://github.com/andreacorbellini/ecc/blob/master/logs/common.py)。

```python
class EllipticCurve:
    """An elliptic curve over a prime field.
    Source: https://github.com/andreacorbellini/ecc/blob/master/logs/common.py

    The field is specified by the parameter 'p'.
    The curve coefficients are 'a' and 'b'.
    The base point of the cyclic subgroup is 'g'.
    The order of the subgroup is 'n'.
    """

    def __init__(self, p, a, b, g, n):
        self.p = p
        self.a = a
        self.b = b
        self.g = g
        self.n = n

        assert pow(2, p - 1, p) == 1
        assert (4 * a * a * a + 27 * b * b) % p != 0
        assert self.is_on_curve(g)
        assert self.mult(n, g) is None

    def is_on_curve(self, point):
        """Checks whether the given point lies on the elliptic curve."""
        if point is None:
            return True

        x, y = point
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def add(self, point1, point2):
        """Returns the result of point1 + point2 according to the group law."""
        assert self.is_on_curve(point1)
        assert self.is_on_curve(point2)

        if point1 is None:
            return point2
        if point2 is None:
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            m = (3 * x1 * x1 + self.a) * inverse_mod(2 * y1, self.p)
        else:
            m = (y1 - y2) * inverse_mod(x1 - x2, self.p)

        x3 = m * m - x1 - x2
        y3 = y1 + m * (x3 - x1)
        result = (x3 % self.p,
                  -y3 % self.p)

        assert self.is_on_curve(result)

        return result

    def double(self, point):
        """Returns 2 * point."""
        return self.add(point, point)

    def neg(self, point):
        """Returns -point."""
        if point is None:
            return None

        x, y = point
        result = x, -y % self.p

        assert self.is_on_curve(result)

        return result

    def mult(self, n, point):
        """Returns n * point computed using the double and add algorithm."""
        if n % self.n == 0 or point is None:
            return None

        if n < 0:
            return self.neg(self.mult(-n, point))

        result = None
        addend = point

        while n:
            if n & 1:
                result = self.add(result, addend)
            addend = self.double(addend)
            n >>= 1

        return result

    def __str__(self):
        a = abs(self.a)
        b = abs(self.b)
        a_sign = '-' if self.a < 0 else '+'
        b_sign = '-' if self.b < 0 else '+'

        return 'y^2 = (x^3 {} {}x {} {}) mod {}'.format(
            a_sign, a, b_sign, b, self.p)


def inverse_mod(n, p):
    """Returns the inverse of n modulo p.

    This function returns the only integer x such that (x * n) % p == 1.

    n must be non-zero and p must be a prime.
    """
    if n == 0:
        raise ZeroDivisionError('division by zero')
    if n < 0:
        return p - inverse_mod(-n, p)

    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, n

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_s - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (n * x) % p == 1

    return x % p

```



#### 参数配置

整数域的椭圆曲线计算需要用到下面这些参数：

- 素数p：定义了有限域的大小
- 参数a：椭圆曲线等式的参数
- 参数b：椭圆曲线等式的参数
- 生成元g：子群的生成元，包含横纵坐标
- 阶n：子群的阶

对应蓝牙的配置参数如下：

```python

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
```



#### is_on_curve()函数

判断点是否在椭圆曲线上，其实就是将x导入椭圆曲线上计算，看所得y是否匹配。



#### add()函数

计算两个点相加的结果，包含两个点相同的场景。



#### double()函数

也就是计算`P+P`或`2P`的结果。





#### neg()函数

计算`P`对应的`-P`。



#### mult()函数

计算`nP`的结果，这里使用了**二进制分解**的方法来加快运算。







### 测试

参考Core Spec v5.4 P903中写的测试用例进行测试。DHKey的计算就是ECDH中计算的S。

```python

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
```





测试结果如下，可以看出不管是A还是B，算出的DHKey都是相同的。

```
###################################################################################
#                                  ecc_P192_test                                  #
###################################################################################
###################################################################################
#                            7.1.1.1 P-192 data set 1                             #
###################################################################################
>>>>>>>>>> Pass <<<<<<<<<<
Calulate PublicA: (0x15207009984421a6586f9fc3fe7e4329d2809ea51125f8ed, 0xb09d42b81bc5bd009f79e4b59dbbaa857fca856fb9f7ea25)
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateB * PublicA) DHKey: (0xfb3ba2012c7e62466e486e229290175b4afebc13fdccee46, 0x54f2e4e8a2999bd1851496c98fba9e41024d1e8389132d8b)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateA * PrivateB * G) DHKey: (0xfb3ba2012c7e62466e486e229290175b4afebc13fdccee46, 0x54f2e4e8a2999bd1851496c98fba9e41024d1e8389132d8b)
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                            7.1.1.2 P-192 data set 2                             #
###################################################################################
>>>>>>>>>> Pass <<<<<<<<<<
Calulate PublicA: (0x45571f027e0d690795d61560804da5de789a48f94ab4b07e, 0x220016e8a6bce74b45ffec1e664aaa0273b7cbd907a8e2b)
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateB * PublicA) DHKey: (0xa20a34b5497332aa7a76ab135cc0c168333be309d463c0c0, 0x44c997511b562f85c0926b339ddd35d46aae75d6fa0d2e71)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateA * PrivateB * G) DHKey: (0xa20a34b5497332aa7a76ab135cc0c168333be309d463c0c0, 0x44c997511b562f85c0926b339ddd35d46aae75d6fa0d2e71)
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                            7.1.1.3 P-192 data set 3                             #
###################################################################################
>>>>>>>>>> Pass <<<<<<<<<<
Calulate PublicA: (0x2ed35b430fa45f9d329186d754eeeb0495f0f653127f613d, 0x27e08db74e424395052ddae7e3d5a8fecb52a8039b735b73)
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateB * PublicA) DHKey: (0x3b3986ba70790762f282a12a6d3bcae7a2ca01e25b87724e, 0xc3e683bebd838de05611d44ecd57d81378c2e377ad0eab18)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateA * PrivateB * G) DHKey: (0x3b3986ba70790762f282a12a6d3bcae7a2ca01e25b87724e, 0xc3e683bebd838de05611d44ecd57d81378c2e377ad0eab18)
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                            7.1.1.4 P-192 data set 4                             #
###################################################################################
>>>>>>>>>> Pass <<<<<<<<<<
Calulate PublicA: (0xf24a6899218fa912e7e4a8ba9357cb8182958f9fa42c968c, 0x7c0b8a9ebe6ea92e968c3a65f9f1a9716fe826ad88c97032)
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateB * PublicA) DHKey: (0x4a78f83fba757c35f94abea43e92effdd2bc700723c61939, 0x3fa999dc821d239ad5390f4c4decac2851d67e218d44a236)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateA * PrivateB * G) DHKey: (0x4a78f83fba757c35f94abea43e92effdd2bc700723c61939, 0x3fa999dc821d239ad5390f4c4decac2851d67e218d44a236)
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                            7.1.1.5 P-192 data set 5                             #
###################################################################################
>>>>>>>>>> Pass <<<<<<<<<<
Calulate PublicA: (0xcbe3c629aceb41b73d475a79fbfe8c08cdc80ceec00ee7c9, 0xf9f70f7ae42abda4f33af56f7f6aa383354e453fa1a2bd18)
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateB * PublicA) DHKey: (0x64d4fe35567e6ea0ca31f947e1533a635436d4870ce88c45, 0x4586ad2ce6ed306414f77eba36281d17d9d1dcfb218c25a5)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateA * PrivateB * G) DHKey: (0x64d4fe35567e6ea0ca31f947e1533a635436d4870ce88c45, 0x4586ad2ce6ed306414f77eba36281d17d9d1dcfb218c25a5)
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                            7.1.1.6 P-192 data set 6                             #
###################################################################################
>>>>>>>>>> Pass <<<<<<<<<<
Calulate PublicA: (0xeca2d8d30bbef3ba8b7d591fdb98064a6c7b870cdcebe67c, 0x2e4163a44f3ae26e70dae86f1bf786e1a5db5562a8ed9fee)
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateB * PublicA) DHKey: (0x6433b36a7e9341940e78a63e31b3cf023282f7f1e3bf83bd, 0x1327a7de7d2fee828f64f08431f9972bee9ed3180600e275)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateA * PrivateB * G) DHKey: (0x6433b36a7e9341940e78a63e31b3cf023282f7f1e3bf83bd, 0x1327a7de7d2fee828f64f08431f9972bee9ed3180600e275)
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                            7.1.1.7 P-192 data set 7                             #
###################################################################################
>>>>>>>>>> Pass <<<<<<<<<<
Calulate PublicA: (0x9f56a8aa27346d66652a546abacc7d69c17fd66e0853989f, 0xd7234c1464882250df7bbe67e0fa22aae475dc58af0c4210)
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateB * PublicA) DHKey: (0xc67beda9baf3c96a30616bf87a7d0ae704bc969e5cad354b, 0xca8efba73a9190b9d136c0424f7ef401d2e69274e15a0f05)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateA * PrivateB * G) DHKey: (0xc67beda9baf3c96a30616bf87a7d0ae704bc969e5cad354b, 0xca8efba73a9190b9d136c0424f7ef401d2e69274e15a0f05)
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                            7.1.1.8 P-192 data set 8                             #
###################################################################################
>>>>>>>>>> Pass <<<<<<<<<<
Calulate PublicA: (0x61c7f3c6f9e09f41423dce889de1973d346f2505a5a3b19b, 0x919972ff4cd6aed8a4821e3adc358b41f7be07ede20137df)
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateB * PublicA) DHKey: (0x6931496eef2fcfb03e0b1eef515dd4e1b0115b8b241b0b84, 0x37405944a0a951fa7d45c174af6426455012b14b866c6571)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateA * PrivateB * G) DHKey: (0x6931496eef2fcfb03e0b1eef515dd4e1b0115b8b241b0b84, 0x37405944a0a951fa7d45c174af6426455012b14b866c6571)
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                            7.1.1.9 P-192 data set 9                             #
###################################################################################
>>>>>>>>>> Pass <<<<<<<<<<
Calulate PublicA: (0x9f09c773adb8e7b66b5d986cd15b143341a66d824113c15f, 0xd2000a91738217ab8070a76c5f96c03de317dfab774f4837)
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateB * PublicA) DHKey: (0xa518f3826bb5fa3d5bc37da4217296d5b6af51e5445c6625, 0xfd65bc92e97b218dfa592ef7e2c3da5e5597f199fa7a9a41)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateA * PrivateB * G) DHKey: (0xa518f3826bb5fa3d5bc37da4217296d5b6af51e5445c6625, 0xfd65bc92e97b218dfa592ef7e2c3da5e5597f199fa7a9a41)
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                           7.1.1.10 P-192 data set 10                            #
###################################################################################
>>>>>>>>>> Pass <<<<<<<<<<
Calulate PublicA: (0xfa2b96d382cf894aeeb0bd985f3891e655a6315cd5060d03, 0xf7e8206d05c7255300cc56c88448158c497f2df596add7a2)
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateB * PublicA) DHKey: (0x12a3343bb453bb5408da42d20c2d0fcc18ff078f56d9c68c, 0xb002a2d73645ea55363d194a7838ae8f37ef3c2f713e96d0)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateA * PrivateB * G) DHKey: (0x12a3343bb453bb5408da42d20c2d0fcc18ff078f56d9c68c, 0xb002a2d73645ea55363d194a7838ae8f37ef3c2f713e96d0)
>>>>>>>>>> Pass <<<<<<<<<<
###################################################################################
#                                  ecc_P256_test                                  #
###################################################################################
###################################################################################
#                             7.1.2 P-256 sample data                             #
###################################################################################
###################################################################################
#                            7.1.2.1 P-256 data set 1                             #
###################################################################################
>>>>>>>>>> Pass <<<<<<<<<<
Calulate PublicA: (0x20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de6, 0xdc809c49652aeb6d63329abf5a52155c766345c28fed3024741c8ed01589d28b)
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
Calulate PublicB: (0x1ea1f0f01faf1d9609592284f19e4c0047b58afd8615a69f559077b22faaa190, 0x4c55f33e429dad377356703a9ab85160472d1130e28e36765f89aff915b1214a)
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateB * PublicA) DHKey: (0xec0234a357c8ad05341010a60a397d9b99796b13b4f866f1868d34f373bfa698, 0x1097c25e6d6e79b669982feca19f50195e0dd493032471c7f1bdfb7ddce7e2b1)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateB * PublicA) DHKey: (0xab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69, 0x58fa9064062cc53073e1ab0a7690d1f955c24c9a98ce9df28c5908e1b36fd5fc)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateA * PublicB) DHKey: (0xab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69, 0x58fa9064062cc53073e1ab0a7690d1f955c24c9a98ce9df28c5908e1b36fd5fc)
>>>>>>>>>> Pass <<<<<<<<<<
Calulate(PrivateA * PrivateB * G) DHKey: (0xab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69, 0x58fa9064062cc53073e1ab0a7690d1f955c24c9a98ce9df28c5908e1b36fd5fc)
>>>>>>>>>> Pass <<<<<<<<<<
```





## SMP CRYPTOGRAPHIC TOOLBOX实现

在Core Spec v5.4 P1549中定义了一系列用于配对的算法库。按照Legacy Pairing和Secure Connection Pairing所使用的函数各不相同。

- `ah`用于创建一个24位的哈希值，用于随机地址的创建和解析。

下列加密函数被定义为支持LE Legacy Pairing过程。

- `c1`用于生成配对过程中使用的确认值。

- `s1`用于在配对过程中生成STK。

以下是为支持LE Secure Connection Pairing过程而定义的加密函数连接的配对过程。

- `f4`用于在配对过程中产生确认值。

- `f5`用于在配对过程中生成LTK和MacKey。

- `f6`用于在配对过程中的认证阶段2中生成检查值。

- `g2`用于在配对过程中的认证阶段1中生成6位数的数字比较值。

- `h6`用于从源自安全连接的BR/EDR链接密钥中生成LE LTK，并用于从源自安全连接的LE LTK中生成BR/EDR链接密钥。

- `h7`用于生成中间密钥，同时从源自安全连接的BR/EDR链接密钥生成LE LTK，并从源自安全连接的LE LTK生成BR/EDR链接密钥。



### ah函数实现

#### 概述

用户生成RPA地址中hash值，输入参数为：

![image-20230222143252277](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222143252277.png)

其中`r'`如下构成，由padding和r共同构成128bits。

![image-20230222143307621](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222143307621.png)

函数缩写如下，其实就是AES-128运算后，保留低24bit。

![image-20230222143326067](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222143326067.png)

#### 算法实现

如下所示，输入k和r，最终输出24bit的ah值。

```python
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
```



#### 测试

参考Core Spec v5.4 P1644中写的测试用例进行测试。注意测试用例中的参数是大端的。

```python
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
```



测试结果如下：

```
###################################################################################
#                                   smp_ah_test                                   #
###################################################################################
###################################################################################
#                      D.7 ah RANDOM ADDRESS HASH FUNCTIONS                       #
###################################################################################
k: 0xec0234a357c8ad05341010a60a397d9b
r: 0x708194
r': 0x00000000000000000000000000708194
ah_full: 0x159d5fb72ebe2311a48c1bdcc40dfbaa
ah: 0x0dfbaa
>>>>>>>>>> Pass <<<<<<<<<<
```









### LE Legacy Pairing相关函数

**注意，LE Legacy Pairing过程只用到了AES-128的加密函数。**

以Just Works为例，显示`c1`和`s1`函数使用的位置和传入的参数。

![image-20230222143046088](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222143046088.png)



#### c1函数实现

##### 概述

用于Legacy Pairing中的确认值计算，输入参数为：

![image-20230222143926172](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222143926172.png)

其中`p1`如下构成，由多个参数共同构成128bits。

![image-20230222143947424](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222143947424.png)

其中`p2`如下构成，由多个参数共同构成128bits。

![image-20230222144021525](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222144021525.png)

函数缩写如下，其实就是进行2次AES-128运算，得到128bits的确认值。

![image-20230222144050206](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222144050206.png)

##### 算法实现

如下所示，输入参数后，最终输出24bit的ah值。

```python

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
```



##### 测试

参考Core Spec v5.4 P1551中写的测试用例进行测试。注意测试用例中的参数是大端的。

```python
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
```



测试结果如下：

```
###################################################################################
#                                   smp_c1_test                                   #
###################################################################################
k: 0x00000000000000000000000000000000
r: 0x5783d52156ad6f0e6388274ec6702ee0
pres: 0x05000800000302
preq: 0x07071000000101
iat: 0x01
ia: 0xa1a2a3a4a5a6
rat: 0x00
ra: 0xb1b2b3b4b5b6
p1: 0x05000800000302070710000001010001
p2: 0x00000000a1a2a3a4a5a6b1b2b3b4b5b6
c1: 0x1e1e3fef878988ead2a74dc5bef13b86
>>>>>>>>>> Pass <<<<<<<<<<
```





#### s1函数实现

##### 概述

用于Legacy Pairing中的Key生成，输入参数为：

![image-20230222144358709](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222144358709.png)

其中`r'`如下构成，而`r1'`取`r1`的低64bits；和``r2'`取`r2`的低64bits`。

![image-20230222144444595](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222144444595.png)

函数缩写如下，其实就是进行AES-128运算，得到128bits的确认值。

![image-20230222144620353](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222144620353.png)

##### 算法实现

如下所示，输入参数后，最终输出128bit的s1值。

```python
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
```



##### 测试

参考Core Spec v5.4 P1551中写的测试用例进行测试。注意测试用例中的参数是大端的。

```python
def smp_s1_test():
    print_header("smp_s1_test")
    k = get_bytes_from_big_eddian_string('00000000000000000000000000000000')
    r1 = get_bytes_from_big_eddian_string('000F0E0D0C0B0A091122334455667788')
    r2 = get_bytes_from_big_eddian_string('010203040506070899AABBCCDDEEFF00')
    s1 = smp_s1(k, r1, r2)

    s1_exp = get_bytes_from_big_eddian_string('9a1fe1f0e8b0f49b5b4216ae796da062')
    print_result_with_exp(s1 == s1_exp)
```



测试结果如下：

```
###################################################################################
#                                   smp_s1_test                                   #
###################################################################################
k: 0x00000000000000000000000000000000
r1: 0x000f0e0d0c0b0a091122334455667788
r2: 0x010203040506070899aabbccddeeff00
r': 0x112233445566778899aabbccddeeff00
s1: 0x9a1fe1f0e8b0f49b5b4216ae796da062
>>>>>>>>>> Pass <<<<<<<<<<
```







### LE Secure Connection Pairing相关函数

**注意，LE Secure Connection Pairing过程只用到了AES-CMAC函数，DHKey的生成用到了ECC P256（椭圆曲线加密）。**

以Just Works为例，显示`c1`和`s1`函数使用的位置和传入的参数。

- Step1：是交互Public Key，然后使用ECC P256（椭圆曲线加密）对DHKey进行计算。

![image-20230222145256661](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222145256661.png)



- Step2，显示在Just Works模式下，认证阶段1中`f4`和`g2`函数使用的位置和传入的参数。

![image-20230222145047147](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222145047147.png)





- Step3，显示在在认证阶段2中`f5`和`f6`函数使用的位置和传入的参数。

![image-20230222145219125](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222145219125.png)



- Step4，用`h6`和`h7`函数进行LTK的转换，由于这里没有经典蓝牙的东西，暂不展开。





#### f4函数实现

##### 概述

用于Secure Connection Pairing中的确认值计算，输入参数为：

![image-20230222150041835](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222150041835.png)

函数缩写如下，其实就是进行1次AES-CMAC运算，得到128bits的确认值。

![image-20230222150154702](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222150154702.png)

##### 算法实现

如下所示，输入参数后，最终输出128bit的f4值。

```python
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
```



##### 测试

参考Core Spec v5.4 P1642中写的测试用例进行测试。注意测试用例中的参数是大端的。

```python
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
```



测试结果如下：

```
###################################################################################
#                                   smp_f4_test                                   #
###################################################################################
###################################################################################
#                 D.2 f4 LE SC CONFIRM VALUE GENERATION FUNCTION                  #
###################################################################################
U: 0x20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de6
V: 0x55188b3d32f6bb9a900afcfbeed4e72a59cb9ac2f19d7cfb6b4fdd49f47fc5fd
X: 0xd5cb8454d177733effffb2ec712baeab
Z: 0x00
m: 0x20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de655188b3d32f6bb9a900afcfbeed4e72a59cb9ac2f19d7cfb6b4fdd49f47fc5fd00
f4: 0xf2c916f107a9bd1cf1eda1bea974872d
>>>>>>>>>> Pass <<<<<<<<<<
```







#### f5函数实现

##### 概述

用于Secure Connection Pairing中的KEY计算，输入参数为：

![image-20230222150434615](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222150434615.png)

用于AES-CMAC运算的Key(`T`)计算如下：

![image-20230222150702139](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222150702139.png)

其中`SALT`为128bits的固定值：

![image-20230222150729080](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222150729080.png)

输入的参数中`keyID`是“btle”对应的ASCII，也就是0x62746C65。

函数缩写如下，其实就是进行2次AES-CMAC运算，分别得到128bits的MacKey和128bits的LTK。

![image-20230222150538358](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222150538358.png)

##### 算法实现

如下所示，输入参数后，最终输出128bits的MacKey和128bits的LTK。

```python
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
```



##### 测试

参考Core Spec v5.4 P1642中写的测试用例进行测试。注意测试用例中的参数是大端的。

```python
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
```



测试结果如下：

```
###################################################################################
#                                   smp_f5_test                                   #
###################################################################################
###################################################################################
#                      D.3 f5 LE SC KEY GENERATION FUNCTION                       #
###################################################################################
W: 0xec0234a357c8ad05341010a60a397d9b99796b13b4f866f1868d34f373bfa698
N1: 0xd5cb8454d177733effffb2ec712baeab
N2: 0xa6e8e7cc25a75f6e216583f7ff3dc4cf
A1: 0x0056123737bfce
A2: 0x00a713702dcfc1
T: 0x3c128f20de88328897624bdb8dac6989
MacKey: 0x2965f176a1084a02fd3f6a20ce636e20
LTK: 0x6986791169d7cd23980522b594750a38
>>>>>>>>>> Pass <<<<<<<<<<
>>>>>>>>>> Pass <<<<<<<<<<
```







#### f6函数实现

##### 概述

用于Secure Connection Pairing中的校验值计算，输入参数为：

![image-20230222151123982](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222151123982.png)



函数缩写如下，其实就是进行AES-CMAC运算，得到128bits的校验值。

![image-20230222151155393](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222151155393.png)

##### 算法实现

如下所示，输入参数后，最终输出128bits的校验值f6。

```python
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
```



##### 测试

参考Core Spec v5.4 P1643中写的测试用例进行测试。注意测试用例中的参数是大端的。

```python
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
```



测试结果如下：

```
###################################################################################
#                                   smp_f6_test                                   #
###################################################################################
###################################################################################
#                  D.4 f6 LE SC CHECK VALUE GENERATION FUNCTION                   #
###################################################################################
W: 0x2965f176a1084a02fd3f6a20ce636e20
N1: 0xd5cb8454d177733effffb2ec712baeab
N2: 0xa6e8e7cc25a75f6e216583f7ff3dc4cf
R: 0x12a3343bb453bb5408da42d20c2d0fc8
IOcap: 0x010102
A1: 0x0056123737bfce
A2: 0x00a713702dcfc1
m: 0xd5cb8454d177733effffb2ec712baeaba6e8e7cc25a75f6e216583f7ff3dc4cf12a3343bb453bb5408da42d20c2d0fc80101020056123737bfce00a713702dcfc1
f6: 0xe3c473989cd0e8c5d26c0b09da958f61
>>>>>>>>>> Pass <<<<<<<<<<
```











#### g2函数实现

##### 概述

用于Secure Connection Pairing中的数值比较值计算，输入参数为：

![image-20230222151442122](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222151442122.png)

函数缩写如下，其实就是进行AES-CMAC运算，并只取低32bits的数值。

![image-20230222151500683](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222151500683.png)

最终使用的数值比较值按照如下公式获取，确保最大6个数字。如，`g2`输出为`0x012eb72a`，对应十进制为`19838762`最终的数值比较值为：`838762`。

![image-20230222151720790](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222151720790.png)

##### 算法实现

如下所示，输入参数后，最终输出32bits的校验值g2。

```python
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
```



##### 测试

参考Core Spec v5.4 P1643中写的测试用例进行测试。注意测试用例中的参数是大端的。

```python
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
```



测试结果如下：

```
###################################################################################
#                                   smp_g2_test                                   #
###################################################################################
###################################################################################
#               D.5 g2 LE SC NUMERIC COMPARISON GENERATION FUNCTION               #
###################################################################################
U: 0x20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de6
V: 0x55188b3d32f6bb9a900afcfbeed4e72a59cb9ac2f19d7cfb6b4fdd49f47fc5fd
X: 0xd5cb8454d177733effffb2ec712baeab
Y: 0xa6e8e7cc25a75f6e216583f7ff3dc4cf
m: 0x20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de655188b3d32f6bb9a900afcfbeed4e72a59cb9ac2f19d7cfb6b4fdd49f47fc5fda6e8e7cc25a75f6e216583f7ff3dc4cf
g2: 0x2f9ed5ba
Compare_Value: 938554
>>>>>>>>>> Pass <<<<<<<<<<
```









#### h6函数实现

##### 概述

用于Secure Connection Pairing中的Link Key转换，输入参数为：

![image-20230222152047939](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222152047939.png)

函数缩写如下，其实就是进行AES-CMAC运算。

![image-20230222152124357](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222152124357.png)



##### 算法实现

如下所示，输入参数后，最终输出128bits的新Key h6。

```python
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
```



##### 测试

参考Core Spec v5.4 P1643中写的测试用例进行测试。注意测试用例中的参数是大端的。

```python
def smp_h6_test():
    print_header("smp_h6_test")
    print_header("D.6 h6 LE SC LINK KEY CONVERSION FUNCTION")
    W = get_bytes_from_big_eddian_string('ec0234a3 57c8ad05 341010a6 0a397d9b')
    keyID = get_bytes_from_big_eddian_string('6c656272')

    h6 = smp_h6(W, keyID)

    h6_exp = get_bytes_from_big_eddian_string('2d9ae102 e76dc91c e8d3a9e2 80b16399')
    print_result_with_exp(h6 == h6_exp)
```



测试结果如下：

```
###################################################################################
#                                   smp_h6_test                                   #
###################################################################################
###################################################################################
#                    D.6 h6 LE SC LINK KEY CONVERSION FUNCTION                    #
###################################################################################
W: 0xec0234a357c8ad05341010a60a397d9b
keyID: 0x6c656272
h6: 0x2d9ae102e76dc91ce8d3a9e280b16399
>>>>>>>>>> Pass <<<<<<<<<<
```







#### h7函数实现

##### 概述

用于Secure Connection Pairing中的Link Key转换，输入参数为：

![image-20230222152300793](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222152300793.png)

函数缩写如下，其实就是进行AES-CMAC运算。

![image-20230222152332673](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222152332673.png)



##### 算法实现

如下所示，输入参数后，最终输出128bits的新Key h7。

```python
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
```



##### 测试

参考Core Spec v5.4 P1644中写的测试用例进行测试。注意测试用例中的参数是大端的。

```python
def smp_h7_test():
    print_header("smp_h7_test")
    print_header("D.8 h7 LE SC LINK KEY CONVERSION FUNCTION")
    SALT = get_bytes_from_big_eddian_string('00000000 00000000 00000000 746D7031')
    W = get_bytes_from_big_eddian_string('ec0234a3 57c8ad05 341010a6 0a397d9b')

    h7 = smp_h6(SALT, W)

    h7_exp = get_bytes_from_big_eddian_string('fb173597 c6a3c0ec d2998c2a 75a57011')
    print_result_with_exp(h7 == h7_exp)
```



测试结果如下：

```
###################################################################################
#                                   smp_h7_test                                   #
###################################################################################
###################################################################################
#                    D.8 h7 LE SC LINK KEY CONVERSION FUNCTION                    #
###################################################################################
W: 0x000000000000000000000000746d7031
keyID: 0xec0234a357c8ad05341010a60a397d9b
h6: 0xfb173597c6a3c0ecd2998c2a75a57011
>>>>>>>>>> Pass <<<<<<<<<<
```







## LE和加密相关HCI

从上述分析可以看出，LE用了对称加密中的AES-128、AES-CMAC和AES-CCM；非对称加密中的ECC P256算法。

按照Host/Controller分层，Host需要用到对称加密中的AES-128和AES-CMAC；非对称加密中的ECC P256。其中AES-CMAC又是由AES-128实现。

### AES-128实现

当采用多Host+Controller分层时，Controller因为必须要实现AES-CCM，必然实现了AES-128算法，所以Host为省Code Size无需再实现AES-128，并且因为Controller一般是有硬件加速，其性能也更好。通过`HCI_LE_Encrypt Command(Opcode: 0x2017)`输入一个Key和一个明文，即可在Command Complete Event得到密文。

![image-20230222153102648](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222153102648.png)

### ECC实现

从之前介绍可以看到ECC原理和其应用场景，在python中由于其原生支持大数乘法，所以代码写起来很小也直观。但是在C语言中想实现256bit的数值运算会非常麻烦，而且运算量也很大。实际ECC使用频次并不高，而且Controller芯片一般有硬件加速支持，完全没必要Host去实现相应的算法。

总结ECDH使用，其可以抽象为两个行为：

#### 公私钥对生成

通过`HCI_LE_Read_Local_P-256_Public_Key Command(Opcode: 0x2025)`生成一个秘钥对，并通过`HCI_LE_Read_Local_P-256_Public_Key_Complete Event`接收当前Controller的P256公钥信息。

**注意，出于安全考虑，HCI接口并不会告知Host当前Controller所使用的的私钥信息。**

![image-20230222153747088](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222153747088.png)

![image-20230222154101637](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222154101637.png)

#### DHKey计算

通过`HCI_LE_Generate_DHKey Command(Opcode: 0x2026)`输入对端的公钥信息，由Controller计算生成DHKey，并通过`HCI_LE_Generate_DHKey_Complete event`接收当前Controller的计算所得的DHKey信息。

![image-20230222153814209](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222153814209.png)

![image-20230222154047244](https://markdown-1306347444.cos.ap-shanghai.myqcloud.com/img/image-20230222154047244.png)









































