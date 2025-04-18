---
title: "Seccon CTF Quals 2024"
date: 2024-05-10
math: true
draft: false
---

Old version of this writeup: [Here](https://hackmd.io/ApQoupblQcy0HGjA-Unbrw)


Another month, another CTF! Last weekend I played the qualifiers for Seccon CTF 2024 with about:blankets. I played remotely 😢 but the new whiteboard gave me and Drago a lot of space to think!
Drago and I were able to solve three crypto challenges 🎉 and, considering the full a:b team, we were able to solve all the crypto challenges 🎉🎉🎉 — we were one of the only two teams to do that. (Dice Gang being the other one)

Here you can find the writeups for dual_summon and tidal_wave. Drago came up with most of the solution for xiyi, so you can find his writeup on his hackmd at: [LINK](https://hackmd.io/@Drago/r1_Kz8IXJx)


# crypto - dual_summon
*Challenge*
* Author: kurenaif (best crypto vtuber ever! Go say 'hello' at https://www.youtube.com/c/kurenaif)
* Solves: 63
* Points: 123

> You are a beginner summoner. It's finally time to learn dual summon

This challenge involves AES in GCM mode. Specifically, we’re tasked with creating a plaintext that, when encrypted under two secret keys, results in the same authentication tag. GCM's rich mathematical structure in $GF(2^{128})$ gives us interesting leverage here.

#### Challenge Details

The server generates two secret keys and a single nonce. We can call an oracle that encrypts a plaintext of our choice and returns its authentication tag, specifying which secret key to use. However, the oracle can only be called 10 times.

````python
#server.py

def summon(number, plaintext):
    assert len(plaintext) == 16
    aes = AES.new(key=keys[number-1], mode=AES.MODE_GCM, nonce=nonce)
    ct, tag = aes.encrypt_and_digest(plaintext)
    return ct, tag

for _ in range(10):
    number = int(input("summon number (1 or 2) >"))
    name   = bytes.fromhex(input("name of sacrifice (hex) >"))
    ct, tag = summon(number, name)
    print(f"monster name = [---filtered---]")
    print(f"tag(hex) = {tag.hex()}")

````

The goal is to execute the dual_summon function successfully:

````python
#server.py

# When you can exec dual_summon, you will win
def dual_summon(plaintext):
    assert len(plaintext) == 16
    aes1 = AES.new(key=keys[0], mode=AES.MODE_GCM, nonce=nonce)
    aes2 = AES.new(key=keys[1], mode=AES.MODE_GCM, nonce=nonce)
    ct1, tag1 = aes1.encrypt_and_digest(plaintext)
    ct2, tag2 = aes2.encrypt_and_digest(plaintext)
    # When using dual_summon you have to match tags
    assert tag1 == tag2

name   = bytes.fromhex(input("name of sacrifice (hex) >"))
dual_summon(name)
print("Wow! you could exec dual_summon! you are master of summoner!")
print(flag)   

````

### Solve
As always, when dealing with GCM we need the following helping functions:

````python
from Crypto.Util.number import bytes_to_long 

F.<a> = GF(2)[]
F.<z> = GF(2^128, name='z', modulus= 1 + a + a^2 + a^7 + a^128 )

def bytes_to_GF(ctx):
    prebin=bin(bytes_to_long(ctx))[2:]
    return F([int(i) for i in "0"*(128-len(prebin))+prebin])

def GF_to_bytes(el):
    pre2=(bin(F(el).integer_representation())[2:])[::-1]
    preint= int(pre2 + "0"*(128-len(pre2)),2)
    return int(preint).to_bytes(length=16,byteorder="big")
````

The plaintext needs to have a fixed length of one block. Recalling the structure of AES-GCM (https://en.wikipedia.org/wiki/Galois/Counter_Mode), we know that the tag can be written as:  
$ tag = Enc_{sk_i}(nonce) + H \cdot(H\cdot(Enc_{sk_i}(nonce+1)+ptx+H\cdot A) +L )$  
where $+$ and $\cdot$ are the field operations of $GF(2^128)$, and $H$, $A$ and $L$ are fixed ($H$ is key-dependent) values.  


We can rewrite this as:  


$ tag= Enc_{sk_i}(nonce) + H^2 \cdot Enc_{sk_i}(nonce+1) + H^2\cdot ptx + H^3 \cdot A + H^2 \cdot L .$  
From this, we can emphasize the (in)dependency of the terms on the plaintext:


$  tag = mask_{sk_i} + H^2\cdot ptx $ 

This means that, by quering the summon oracle with $ptx=0$ for each of the keys we can obtain $mask_{sk_0}$ and $mask_{sk_1}$.
Also, by quering the oracle again with any plaintext, we can recover the value of $H^2$ for both secret keys just by subtracting the mask and dividing for the plaintext.

Having both masks and $H^2$ for both secret keys, now we can just consider the equality between the two tags to obtain the desired plaintext for the dual summon:  


$ mask_{sk_0} + H_{sk_0}^2\cdot ptx = mask_{sk_1} + H_{sk_1}^2\cdot ptx$    

$ ptx = \frac{mask_{sk_1}-mask_{sk_0}}{H_{sk_0}^2 - H_{sk_1}^2}  $

Here is the Sagemath code:
```` python
ptx0= GF_to_bytes(F(0))
ptx1= GF_to_bytes(F(1))

summ0= summon(0,ptx0)
mask= bytes_to_GF(summ0)

summ1= summon(0,ptx1)
Hsq= bytes_to_GF(summ1)-mask

summ2= summon(1,ptx0)
mask2= bytes_to_GF(summ2)

summ3= summon(1,ptx1)
Hsq2= bytes_to_GF(summ3)-mask2

ptx= GF_to_bytes((mask-mask2)/(Hsq-Hsq2))
dual_summon(ptx)
````

# crypto - Tidal wave
*Challenge*
* Author: kurenaif 
* Solves: 19
* Points: 210

> A torrent of data.

The code has many constructions, so let’s analyze it step by step, starting from the end goal.

1. The flag is encrypted with AES with key "keyvec"

````python
keyvec = vector(R, [get_Rrandom(R) for _ in range(k)])

key = hashlib.sha256(str(keyvec).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
encrypted_flag = cipher.encrypt(pad(flag, AES.block_size))
````

2. Keyvec is encrypted by multiplying it for a secret matrix $G$ and by adding an error vector with a specific structure. The errors are either $0$s or multiples of $p$ or $q$, where $p,q$ are large unknowns primes from a RSA module.

````python
prime_bit_length = 512
p = getPrime(prime_bit_length)
q = getPrime(prime_bit_length)
N = p*q
R = Zmod(N)

def make_random_vector2(R, length):
    error_cnt = 28
    res = vector(R, length)
    error_pos = random.sample(range(length), error_cnt)
    for i in error_pos[:error_cnt//2]:
        res[i] = get_Rrandom(R)*p
    for i in error_pos[error_cnt//2:]:
        res[i] = get_Rrandom(R)*q
    return vector(R, res)

key_encoded = keyvec*G + make_random_vector2(R, n)
````

3. $p$ is also encrypted by multiplying it for the same secret matrix $G$ and by adding a big (aaaaalmost uniform) error to it.

```` python
def make_random_vector(R, length):
    error_range = 2^1000
    res = []
    for _ in range(length):
        res.append(R(secrets.randbelow(int(error_range))))
    return vector(R, res)
    
p_encoded = pvec*G + make_random_vector(R, n)
````
4. Finally, we have some information about $G$. In particular, $G$ is a Vandermonde matrix of a list of secret $\alpha_i$, of which we know the squares $\alpha_i^2$ and a RSA encryption of the sum $(\sum\alpha_i)^{65537}$. We also know the determinant of five submatrixes of $G$, therefore $\prod_{i<j}(\alpha_j-\alpha_i)$ for $i,j\in\{0,\dots,7\},\{7,\dots,14\},\dots,\{28,\dots,35\}$.

````python
alphas = vector(R, [get_Rrandom(R) for _ in range(n)])
G = Vandermonde(R, alphas)

dets = [G.submatrix(0,i*k-i,8,8).det() for i in range(5)]
double_alphas = list(map(lambda x: x^2, alphas))
alpha_sum_rsa = R(sum(alphas))^65537
````

### Pre-Solve
(Spoiler) Understading that these sub-problems can be solved sequentially, 4 to 1, was not immediate. In particular, sub-problem 4 seems to have not enough information for an algebraic attack. The only info we have are some determinants (that are really high degree polynomials hard to relinearize) and some squares in a ring where computing square roots is hard. Therefore, as a first approach, we tried to merge points 3 and 4 in a bigger problem.
This detour involved 90 minutes of messy algebraic computations, only to eventually circle back to the original problem.

Here’s a photo of the process:![4_and_3_combined](https://hackmd.io/_uploads/BJjC0JMXyg.jpg)



### Solve
After deciding that merging 3 and 4 is a mistake, we focused on how to solve 4 on its own. The key idea (thanks to Drago) was to use Gröbner bases. We didn't want to try it at first because the number of equations that we had seemed low and the determinant had really high degree. Apparently our faith in Gröbner was too low and having the squares is already really powerful to isolate ideals on a polynomial ring, even if you cannot compute square roots directly!

So, after convincing Sage that we were actually working on the polynomial ring of a field ([Fun Picture Of It](https://bsky.app/profile/drago1729.bsky.social/post/3lbrcuj2pfk26)), we were able to use Gröbner to obtain the alphas (or at least the relations between them):

````python
#Here we are using made up values. 
#In the real execution we just imported the challenge ones.

n = 8
RN = Zmod(N)

def retTrue():
    return True

RN.is_field = retTrue

alphas = [RN(randint(1, N)) for _ in range(n)]
a2 = [a^2 for a in alphas]
A = matrix.vandermonde(alphas)
dd = A.det()

R = PolynomialRing(RN, [f"x_{i}" for i in range(n)])
xx = R.gens()
sq_polys = [xx[i]^2 - a2[i] for i in range(n)]
RQ = R.quotient(R.ideal(sq_polys))
xxbar = [RQ(x) for x in xx]

minor = matrix.vandermonde(xxbar).det()
I = R.ideal([minor.lift()-dd]+sq_polys)
I.groebner_basis()

````

The result was obtaining the linear relation between each couple of $(\alpha_i,\alpha_j)$. This allowed us to express all the secret alphas as $\lambda_i\cdot\alpha_{35}$. To finally obtain the values we used the encryption of the sum of the $\alpha$ that we were given. In particular, $(\sum\alpha_i)^{65537}= (\sum\lambda_i)^{65537}\cdot\alpha_{35}^{65537}$. Since we also knew determinants of the submatrixes, we had $\prod_{i<j}(\lambda_j-\lambda_i)\alpha_{35}^{24}$. If we compute xgcd on 65537 and 24, we obtain $a*24+b=65537=1$ that allows us to find $\alpha_{35} = (\alpha_{35}^{24})^a \cdot (\alpha_{35}^{65537})^b$. And therefore all the other alphas.

Now that we solved 4. we know $G$ and we can continue with 3.

By knowing $G$ we now have a lattice (the one generated by $G$ itself) where we can work on. Here, we know that 
$$ split(p) \cdot G + E = p\_enc$$
therefore, we can construct a CVP. The lattice is:
$\begin{pmatrix}
	G & 1_{36} & 0_{36}  & 0_{36}\\
	1 & 0 & 1 & 0 \\ 
    -N* 1 & 0 &0 & 0
\end{pmatrix} $   

and we are trying to recover the vector 
$\begin{pmatrix}
	p\_enc\\
	split(p) \\ 
    E \\
    ks
\end{pmatrix} $
where the $ks$ are the multiples of $N$ that where added for the equality to hold over the integers. Of this vector we know exactly p_enc and we have good bounds on the size of $split(p)$. 

We now run any CVP solver  with bounds on the entries: fixed p_enc, $split(p)<2^{64}$, $E<2^{1000}$ and $ks<2^{67}$ to obtain a result for this vector and to extract a value of $split(p)$. 
(thanks RKM :heart: https://github.com/rkm0959/Inequality_Solving_with_CVP)

````python
A = block_matrix(ZZ, [[Matrix(ZZ, G), 1, 0, 0],[1, 0, 1, 0], [-N, 0, 0, 1]], subdivide=False)
lbounds = list(vector(ZZ, p_encoded)) + [0]*8 + [0]*36 + [0]*36
ubounds = list(vector(ZZ, p_encoded)) + [2^64]*8 + [2^1000]*36 + [2^67]*36
solve(A, lbounds, ubounds)
````

Unfortunately, if we try to divide $N$ with this $p$, it doesn't work. The problem is that, when looking at the equation $split(p)\cdot G$, we obtain that each row is of the following shape $$ p_0+p_1\cdot\alpha+ \dots +p_7\cdot\alpha^7 +e = p\_enc $$ We notice that $p_0$ is never multiplied for $\alpha$ and, therefore, is not fixed/distinct from the error. Luckily, when having at least half of the value of $p$ in an RSA module, is possible to fully factor it using Coppersmith, so it is still possible to recover $p_0$ from the incorrect $split(p)$.

````python
R.<t> = PolynomialRing(Zmod(N), "t")
f = t+sum(2^(64*i)*pvec[i] for i in range(1,8))
f.small_roots(beta=0.4)
````


Now that we have $p$, we can factor $N$ to find $q$ and proceed to the next section.

Here, the key is encrypted again as a product with $G$ (that we know) but the error vector is created in a different, easier, way. The error vector has 36 slots, of which 14 are multiples of $p$, 14 are multiples of q and 8 are zeroes. To solve this without $p$ and $q$, we would need to guess the $8$ positions of the zeroes. In this case we would have a noiseless linear system modulo $N$ that we could easily solve. Unfortunately, guessing correctly 8 out of 36 is negligible.

By knowing $p$, we can look at this problem modulo $p$. In this setting the error vector has $22$ zeroes and $14$ multiples of $q$. Guessing correctly $22$ slots out of $36$ is easily bruteforceable. We just guess $8$ position, pretend the linear system is noiseless and solve it. If we start getting the same solution for multiple positions guesses, then we know that that one is the correct solution mod $p$. We repeat the same process mod $q$ and then we combine with CRT to obtain keyvec. 

````python
from itertools import combinations
from collections import Counter
from random import sample

cnt = Counter()

Kp = GF(p)

while True:
    indices = sample(range(36), 8)
    vals = [Kp(alphas[j]) for j in indices]
    targets = [key_encoded[j] for j in indices]
    M = matrix.vandermonde(vals)
    sol = M^(-1) * vector(Kp, targets)
    cnt[tuple(sol)] += 1
    if cnt.most_common(1)[0][1] >= 3:
        print(sol)
        break
        
keyvec = tuple([crt([keyp[i], keyq[i]], [p, q]) for i in range(8)])

````

We conclude by using keyvec for the AES decryption of the flag.

# crypto - xiyi
*Challenge*
* Author: y011d4
* Solves: 4
* Points: 393

> Calculate \sum_i x_i y_i secretly

Drago came up with most of the solution so you can find a full writeup on his hackmd at: [LINK](https://hackmd.io/@Drago/r1_Kz8IXJx)
