from Crypto.Cipher import AES
from secrets import token_bytes
from base64 import b64encode,b64decode
from Crypto.Util.Padding import pad,unpad

key = token_bytes(16)
def encryptCBC(msg):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(msg, AES.block_size))
    print(ct_bytes)
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv,ct
def decryptCBC(iv,ct):
    try:
        iv = b64decode(iv)
        ct = b64decode(ct)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt
    except (ValueError, KeyError):
        print("Incorrect decryption") 

def encryptEAX(msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce,ciphertext,tag
encryptEAX("asdasd")
def decryptEAX(nonce, ciphertext,tag):
    cipher = AES.new(key,AES.MODE_EAX,nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False
def encryption():
    msg = input('Enter a message:')
    msg = bytes(msg, 'utf-8')
    iv , ct = encryptCBC(msg)
    print(f'The Initialization Vector is, {iv}')
    print(f'The key is, {key}')
    print(f'The first ciphertext is, {ct}')
    nonce, ciphertext, tag= encryptEAX(ct)
    print(f'The second ciphertext is, {ciphertext}')
    firstDecryption = decryptEAX(nonce,ciphertext,tag)
    if not firstDecryption:
        print('message is corrupted')
    else:
        print(f'The first decryption is, {firstDecryption}')
    originalMSG = decryptCBC(iv,firstDecryption).decode("utf-8")
    print(f'The original message, {originalMSG}')
encryption()
