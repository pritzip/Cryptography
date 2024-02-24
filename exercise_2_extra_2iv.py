from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad



#----------------------------------------------------------------------------------------------#


def encrypt_message(key, message, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return ciphertext


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

    # Generate two random IVs
    iv1 = get_random_bytes(16)
    iv2 = get_random_bytes(16)

    # Encrypt the message with two different IVs
    ciphertext1 = encrypt_message(key, message, iv1)
    print(f'Encrypted message with first IV: {ciphertext1}')
    ciphertext2 = encrypt_message(key, message, iv2)
    print(f'Encrypted message with second IV: {ciphertext2}')

    # Decrypt the message with the corresponding IVs
    decrypted_message1 = decrypt_message(key, iv1, ciphertext1)
    print(f'Decrypted message with first IV: {decrypted_message1}')
    decrypted_message2 = decrypt_message(key, iv2, ciphertext2)
    print(f'Decrypted message with second IV: {decrypted_message2}')


#----------------------------------------------------------------------------------------------#
    
if __name__ == '__main__':
    main()