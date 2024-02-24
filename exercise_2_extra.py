from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

#----------------------------------------------------------------------------------------------#


def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return cipher.iv, ciphertext

#----------------------------------------------------------------------------------------------#

def decrypt_message(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

#----------------------------------------------------------------------------------------------#

def main():
    # Generate a random 128-bit key
    key = get_random_bytes(16)

    # The message to encrypt
    message = b'Auto einai ena dokimastiko minuma gia ton elegxo tou script'

    # Encrypt the message
    iv, ciphertext = encrypt_message(key, message)
    print(f'Encrypted message: {ciphertext}')

    # Decrypt the message
    decrypted_message = decrypt_message(key, iv, ciphertext)
    print(f'Decrypted message: {decrypted_message}')


#----------------------------------------------------------------------------------------------#

if __name__ == '__main__':
    main()
