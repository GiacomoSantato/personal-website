---
title: "Codegate CTF Quals 2024"
date: 2024-11-25
math: true
draft: false
---

Old version of the writeup: [LINK](https://hackmd.io/CNE7wlkITNS6Oh0cHTJbww)


A couple of weeks ago, I played the preliminaries for Codegate CTF 2024 with about:blankets. We managed to qualify for the finals in Seoul! I was able to join for most of the 24 hours and it was really nice to come back to the CTF world after three/four really busy months.


# crypto - Cogechan_Dating_Game
*Challenge*
* Author: BaaaaaaaaaaaaaaaaaaaaaaarkingDog
* Solves: 15
* Points: 306

> Love Wins All

The challenge consists of multiple files. The most important ones are `server.py` and `load_and_save.py`. The first one handles the main game and allows you to act in the game. The second one, instead, contains all the main checks to load and save the game.

````python
#server.py
def go(sock):
    sock.settimeout(60) # No response for 60s then connection will be closed.
    # trying to load a save file based on ID, PW first
    ID_len = int.from_bytes(sock.recv(2), 'little')
    ID = sock.recv(ID_len).decode()
    PW_len = int.from_bytes(sock.recv(2), 'little')
    PW = sock.recv(PW_len).decode()

    status, character = load(ID, PW)

    sock.send(status.to_bytes(1, 'little'))

    if status == load_and_save.LOAD_SUCCESS:
        sock.send(len(character.nickname).to_bytes(2, 'little') + character.nickname.encode())
        sock.send(character.day.to_bytes(4, 'little'))
        sock.send(character.stamina.to_bytes(4, 'little'))
        sock.send(character.intelligence.to_bytes(4, 'little'))
        sock.send(character.friendship.to_bytes(4, 'little'))
        
    if status != load_and_save.LOAD_SUCCESS:
        nickname_len = int.from_bytes(sock.recv(2), 'little')
        character.nickname = sock.recv(nickname_len).decode('utf-8', 'ignore')
        character.stamina = 100

    while True:
        com = int.from_bytes(sock.recv(1), 'little')
        if com == 0: # Meaning that connection is closed
            if DEBUG:
                print("connection closed")
            exit()

        elif com == EAT_COMMAND:
            rnd = random.randint(1, 4)
            sock.send(rnd.to_bytes(1, 'little'))
            character.stamina += rnd
            character.day += 1

        elif com == PWN_COMMAND:
            rnd = random.randint(1, 4)
            sock.send(rnd.to_bytes(1, 'little'))
            if character.stamina >= 10:
                character.stamina -= 10
                character.intelligence += rnd
                character.day += 1

        elif com == SLEEP_COMMAND:
            rnd = random.randint(1, 4)
            sock.send(rnd.to_bytes(1, 'little'))
            character.stamina += rnd
            character.day += 1
            pass

        elif com == DATE_COMMAND:
            rnd = random.randint(1, 4)
            sock.send(rnd.to_bytes(1, 'little'))
            if character.stamina >= 10 and character.intelligence.bit_length() >= character.friendship:
                character.stamina -= 10
                character.friendship += 1
                character.day += 1
                if character.friendship == 34:
                    flag = read_flag()
                    sock.send(len(flag).to_bytes(2, 'little') + flag.encode())
                
        elif com == SAVE_COMMAND:
            file_data_enc_len = int.from_bytes(sock.recv(2), 'little')
            file_data_enc = sock.recv(file_data_enc_len)
            tag = sock.recv(16)
            status = load_and_save.save_game(ID, PW, character, file_data_enc, tag)
            sock.send(status.to_bytes(1, 'little'))
        

````

````python
#load_and_save.py

def decrypt_and_parse_save_data(key, nonce, save_data, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    file_data = unpad(cipher.decrypt_and_verify(save_data, tag), 16)
    idx = 0
    nickname_len = int.from_bytes(file_data[idx:idx+2], 'little')
    idx += 2
    nickname = file_data[idx:idx+nickname_len].decode('utf-8', 'ignore')
    idx += nickname_len
    day = int.from_bytes(file_data[idx:idx+4], 'little')
    idx += 4
    stamina = int.from_bytes(file_data[idx:idx+4], 'little')
    idx += 4
    intelligence = int.from_bytes(file_data[idx:idx+4], 'little')
    idx += 4        
    friendship = int.from_bytes(file_data[idx:idx+2], 'little')
    character = Character.Character(nickname, day, stamina, intelligence, friendship)
    return character

def id_pw_validity_check(ID, PW):
    if len(ID) < 20 or len(PW) < 20:
        return False
    if len(set(ID)) < 20 or len(set(PW)) < 20:
        return False
    if ID == PW:
        return False
    return True

def load_game(ID, PW):
    if not id_pw_validity_check(ID, PW):
        return LOAD_FAIL, None

    id_hash = hashlib.sha256(ID.encode()).digest()
    pw_hash = hashlib.sha256(PW.encode()).digest()
    nonce = id_hash[:12]
    file_name = id_hash[16:24].hex()
    key = pw_hash[:16]

    # read save file
    try:
        with open(f'save/{file_name}', 'rb') as f:
            raw_data = f.read()
            file_data_enc = raw_data[:-16]
            tag = raw_data[-16:]
    except Exception as e:
        return LOAD_FAIL, None

    # parse it!
    try:
        character = decrypt_and_parse_save_data(key, nonce, file_data_enc, tag)
    except Exception as e: # error during decryption
        print("LOAD!!", e)
        return LOAD_FAIL, None

    return LOAD_SUCCESS, character

def save_game(ID, PW, character, save_data, tag):
    if not id_pw_validity_check(ID, PW):
        return SAVE_FAIL

    id_hash = hashlib.sha256(ID.encode()).digest()
    pw_hash = hashlib.sha256(PW.encode()).digest()
    nonce = id_hash[:12]
    file_name = id_hash[16:24].hex()
    key = pw_hash[:16]

    try:
        character_parse = decrypt_and_parse_save_data(key, nonce, save_data, tag)
        if character.day != character_parse.day or \
           character.stamina != character_parse.stamina or \
           character.intelligence != character_parse.intelligence or \
           character.friendship != character_parse.friendship:
            
            return SAVE_FAIL

        if character.friendship >= 20: # Please do not save almost-cleared one
            return SAVE_FAIL
        

    except Exception as e: # error during decryption
        print("SAVE!!", e)
        return SAVE_FAIL

    try:
        with open(f'save/{file_name}', 'wb') as f:
            f.write(save_data)
            f.write(tag)
    except:
        return SAVE_FAIL, None

    return SAVE_SUCCESS
````


In this challenge, our objective is to play a dating game. The win condition is to ask for a date while the attributes of our character are: friendliness$=33$, stamina$>=10$ and intellect>=$2^{33}$. 

Reaching these attributes while playing honestly is not feasible, so we need to look at all the options that the server/game grants us in order to find a way to artificially increase our stats.

While connected to the server, playing a game, we are allowed to save and reload the game in a particular way. 
### First play and Save:
* When we connect, we specify a couple of $(ID,PWD)$ that the server uses to craft a $nonce$ and a $file name$, from $sha256(IV)$, and a $key$, from $sha256(PWD)$.
* Then, we can either play the game (by doing $Sleep$, $Pwn$, $Eat$ or $Date$) or request to $Save$.
* If we $Save$, the server asks us to send a couple ($ctx$,$tag$) to store as a save file for the ongoing game.
* To check if we have sent a valid save file, the server immediately takes the $n=nonce$ and $k=key$ from the current session and checks if: 
    1. The couple $(ctx,tag)$ is a valid ciphertext in AES-GCM with the key $k$ and the nonce $n$.
    2. The attributes of the character contained in the save file, after decryption, match with the current attributes in the ongoing game.
* If all the checks are successful, it stores our $(ctx,tag)$ in the file $file name$.

### Load
* When connecting another time, the server asks us $ID$ and $PWD$ and derives again $n=nonce$, $file name$ and $k=key$.
* If the server already contains a file $filename$, then it checks if the couple $(ctx,tag)$ that was stored in $filename$ is a valid ciphertext in AES-GCM with the key $k$ and the nonce $n$.
* If the check is successful, it reads the attributes of the character from the decryption of $ctx$ and uses them for the ongoing game.


### Base attack idea
To cheat the system, we want to connect to the server with two different passwords $PWD_1$ and $PWD_2$ (and, therefore, with two different keys $k_1$ and $k_2$). In this way, the server will perform the saving checks under the key $k_1$ and the loading checks under the key $k_2$. 
This allows us to craft a special ciphertext $ctx$ that, when decrypted under the key $k_1$, will be seen as the weak start-game character that we are using before the save but, when decrypted under the key $k_2$, will be seen as a strong end-game character that is ready to ask for the final $Date$.

### The "decrypt_and_parse_save_data" function
To understand how to craft such a ciphertext, we first need to understand how the server "reads" a save file. After decrypting it with $n$ and $k$, the plaintext gets translated to attributes following the following scheme:
* $nick_{len}$: The first two bytes are the length of the nickname.
* $nick$: The following $nick_{len}$ bytes are the nickname.
* $days$: The following 4 bytes are the days.
* $stam$: The following 4 bytes are the stamina.
* $inte$: The following 4 bytes are the intellect.
* $fr$: The following 2 bytes are the friendship.

A fresh new character, with no nickname, would have, as a save-file plaintext, the following 16-byte (1 AES block) representation: $$P_1 = 00|0000|stam|0000|00,$$ where $stam$ is the 4-bytes representation of the decimal $100$. 

An end-game character, instead, needs to have as a save-file plaintext the following representation: $$P_2=nick_{len}|nick|0000|STAM|INTE|FR,$$ where $STAM$ is the 4-bytes representation of the decimal $2^{32}-1$ (any number greater than 50 would have worked, but hey let's boost these stats!), $INTE$ is the 4-bytes representation of the decimal $2^{32}-1$ (this time, we need this value because we need to reach $2^{32}$ to have a successful $Date$) and $FR$ is the 2-bytes representation of the decimal $33$ (again, we need this exact value for the $Date$).

### "Ambiguous" ciphertext: how to craft it and how to find the keys

This parsing is really important, because it allows us to encrypt two different sets of attributes in two different positions of the ciphertext just by modifying the value $nick_{len}$. 
In particular, we want to focus on a three-blocks ciphertext. The idea is to have a first block that contains the attributes that we need to pass the saving check and a third block that contains the attributes that we want after the load. (The second block will be a magical tool that we will be using later.)

First of all, we fix a $ID$. Any $ID$. We just need it for choosing the same file $file name$ during different connections. We won't need to act on the $n=nonce$ of the AES_GCM in the following attack, so we just fix an $ID$ and we always use it when communicating with the server. 

Now, we fix a key $k_1$ by just fixing any password $PWD_1$. Again, any $PWD_1$ is okay. We compute the first block $ctx_1$ of the ciphertext as the encryption of $P_1$ under the key $k_1$ and the nonce $n$. This allows us to pass the check (2.) during the save.

Finding the key $k_2$ will require a little bit more effort. 

To trick the server, for the loading part, we need the same first ciphertext block $ctx_1$ to decrypt (under key $k_2$) to a plaintext that starts with the 2-bytes representation of the decimal 30. In this way, when reading the save file, the server will consider the remaining first block (14 bytes) and all the second block (16 bytes) as part of the nickname and will ignore them. After this, it will read the attributes from the decryption of the third block (14 bytes). 

This means that we can fix the third block of the ciphertext as $ctx_3 \leftarrow Enc(k_2,P_3)$, with
$$ P_3= 0000|STAM|INTE|FR|PD,  $$where $STAM$, $INTE$, $FR$ are as in $P_2$ and $PD$ is to get a valid padding for the block, therefore the 2-byte representation of the hex $02$ $02$. 

An additional requirement for this ciphertext $ctx=(ctx_1|ctx_2|ctx_3)$ to be valid is that $Dec(k_1,ctx)$ satisfies the padding. So we also need to specify, for example, that the last byte of this decryption needs to be the byte representation of the decimal $1$.

Finding a key $k_2$ that satisfies both of these requirements can be done by just sampling values for $PWD_2$ again and again, and checking that the first two bytes of $Dec(k_2,ctx_1)==30_{10}$ and that the last byte of $Dec(k_1,ctx_3)==1_{10}$. This happens with probability around $2^{-24}$, we can brute force this.

````python
aes_ctr_K1 = AES.new(key1, AES.MODE_CTR, nonce=nonce, initial_value=int(2))

ptx1=bytes.fromhex("00 00") + bytes.fromhex("00 00 00 00") + int(100).to_bytes(4, "little") + bytes.fromhex("00 00 00 00") + bytes.fromhex("00 00") # name length + days + STAMINA!!! + int + friendship
ctx1=aes_ctr_K1.encrypt(ptx1)

ptx3= bytes.fromhex("00 00 00 00") + bytes.fromhex("FF FF FF FF")+ bytes.fromhex("FF FF FF FF") + int(33).to_bytes(2, "little")  + bytes.fromhex("02 02") #days + stamina + INT + friendship + PAD # NEED CHARACTER NAME LENGTH TO DECRYPT TO 2*AES.BLOCKLEN-2
alphabet="qu4DR0PhIWETYlKJGFSZXCVBNMmnbvcx"

for PW2 in tqdm(itertools.combinations(alphabet,20)):
    # PW2 = "pHiquRWEKGFSXCBNMbvc"
    PW2 = ''.join(PW2)
    pw_hash = hashlib.sha256(PW2.encode()).digest()
    key2 = pw_hash[:16]

    aes_ctr_K1 = AES.new(key1, AES.MODE_CTR, nonce=nonce, initial_value=int(2+2))
    aes_ctr_K2 = AES.new(key2, AES.MODE_CTR, nonce=nonce, initial_value=int(2))
    ptx1_tmp = aes_ctr_K2.decrypt(ctx1)
    aes_ctr_K2 = AES.new(key2, AES.MODE_CTR, nonce=nonce, initial_value=int(2+2))
    ctx3_tmp = aes_ctr_K2.encrypt(ptx3)
    if ptx1_tmp[:2]==int(30).to_bytes(2, "little") and aes_ctr_K1.decrypt(ctx3_tmp)[-1] == 1:
        print(f"{PW2 = }")
        # break
        

print("DONE")
print(f"{key2.hex() = }")

````

### THE TAG
"We have the ciphertext and we have the keys! What else do we need?". Unfortunately, the server also performs a verification check for the validity of the ciphertext by using the tag. This happens both when we save and when we load, so we need the same tag to verify on the same ciphertext in both schemes! (AES.GCM with key $k_1$ and AES.GCM with key $k_2$)

The tag$(k=key,n=nonce,ctx)$ is computed in the following way:
* Consider all the 16-bytes elements in the scheme (i.e. $ctx_1$,$ctx_2$,$ctx_3$) as elements of the Galois Field $GF(2^{128})$ (with representative polynimal $f = 1 + a + a^2 + a^7 + a^{128}$).
* Compute $H_k$ as $AES_k(0_{B})$. [$0_B$ is the 16-byte representation of $0$]
* Compute $LEFT_k$ as $AES_k(n|0001)$. [The argument is the content of the counter in GCM before the first encryption]
* Compute $LEN$ as the element of $GF(2^{128})$ corresponding to the block: 8-byte representation of $0$ | 8-byte representation of $8\cdot3\cdot16$.
* The tag is equal to $$(H_k\cdot(H_k\cdot(H_k\cdot ctx_1+ctx_2)+ctx_3)+LEN)+LEFT_k$$

```python
def compute_tag(ctx,key,nonce):
    IV = nonce + long_to_bytes(1,4)
    EK=AES.new(key,AES.MODE_ECB)
    LEFT = int_to_GF128(int.from_bytes(EK.encrypt(IV), "big"))
    H = int_to_GF128(int.from_bytes(EK.encrypt(bytes(16)), 'big'))

    l=len(ctx)//16
    t=int_to_GF128(int(0))
    for i in range(l):
        t+=int_to_GF128(int.from_bytes(ctx[16*i:16*(i+1)], "big"))
        t*=H
    LEN= ((8 * 0) << 64) | (8 * l * 16) 
    t += int_to_GF128(LEN)
    t *= H
    t += LEFT
    return GF128_to_int(t).to_bytes(16,"big")

```

Since we have already fixed $ctx_1$, $ctx_3$, $k_1$ and $k_2$, the only remaining variable is $ctx_2$. This means that we can impose equality between the two tags of the two schemes.
$$ tag(k_1,n,ctx_1|ctx_2|ctx_3)=tag(k_2,n,ctx_1|ctx_2|ctx_3) $$ $$ tag_{k_1}(ctx_2)=tag_{k_2}(ctx_2) $$ After expanding the computations, we obtain that 
$$ ctx_2 = [ctx_1 \cdot (H_{k_1}^4 + H_{k_2}^4) + ctx_3 \cdot (H_{k_1}^2 +H_{k_2}^2) + $$ $$+ LEN \cdot (H_{k_1} + H_{k_2}) + LEFT_{k_1} + LEFT_{k_2}]/(H_{k_1}^3 + H_{k_2}^3)$$

```python
R.<a> = PolynomialRing(GF(2))
f = 1 + a + a^2 + a^7 + a^128
F128.<b> = GF(2).extension(f)
z = int_to_GF128(3)

IV1 = nonce + long_to_bytes( 1 ,4)

EK1 = AES.new(key1, AES.MODE_ECB)
LEFT1 = EK1.encrypt(IV1)
H1 = EK1.encrypt( bytes(16) )

EK2 = AES.new(key2, AES.MODE_ECB)
LEFT2 = EK2.encrypt(IV1)
H2 = EK2.encrypt( bytes(16) )

endianness = "big"

H1 = int_to_GF128(int.from_bytes(H1, endianness))
LEFT1 = int_to_GF128(int.from_bytes(LEFT1, endianness))

H2 = int_to_GF128(int.from_bytes(H2, endianness))
LEFT2 = int_to_GF128(int.from_bytes(LEFT2, endianness))

LEN = int_to_GF128(int.from_bytes(bytes(8) + int(16*8*3).to_bytes(8, "big")))

ctx1_num = int_to_GF128(int.from_bytes(ctx1, endianness))
ctx3_num = int_to_GF128(int.from_bytes(ctx3, endianness))


ctx2_num = (ctx1_num*(H1**4 + H2**4) + ctx3_num*(H1**2 + H2**2) + LEN*(H1 + H2) + LEFT1 + LEFT2)/(H1**3 + H2**3)

ctx2 = GF128_to_int(ctx2_num).to_bytes(16, "big")

final_ctx = ctx1 + ctx2 + ctx3
```

### Recap
The attack works as follows:
* We connect to the server for a new game with credentials $(ID,PWD_1)$.
* We immediately ask to save the game and send $(ctx,tag)$ to the server.
* The server here performs two checks
    1. Verifies $tag$ with $ctx$ for the scheme AES.GCM with key $k_1$. This check is successful because we computed the tag honestly.
    2. Decrypts $ctx$ with $k_1$ and checks if the parameters are the same as the ongoing game. This is confirmed because the parsing function only reads the decryption of the first block, which is exactly the desired $P_1$.
* The server saves $(ctx,tag)$. We disconnect.
* We now connect to the server with credentials $(ID,PWD_2)$.
* The server verifies $tag$ with $ctx$ for the scheme AES.GCM with key $k_2$. This check is successful because of how we crafted $ctx_2$.
* The server reads the character attributes from $Dec(k_2,ctx)$. From this it skips the first two blocks as the nickname and considers the third block, which is exactly equal to $P_3$.
* This game is almost won! We just need to perform a successful $Pwn$ and a $Date$ to capture the FLAG! We can easily do them honestly from the client.

### Post Scriptum
After the end of the challenge, I discovered that this attack (in a slightly different version) was already known from a [2019 Crypto paper](https://eprint.iacr.org/2019/016). The Salamander attack on AES-GCM is the technique we used when crafting the ambiguous ciphertext.

