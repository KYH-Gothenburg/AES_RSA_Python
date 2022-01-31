import os.path

from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


def aes_encrypt(message):
    # Generate a random 128 bits (16 bytes) long key to be used for encryption/decryption
    key = get_random_bytes(16)

    # Create an AES object
    cipher_aes = AES.new(key, AES.MODE_EAX)

    # Encrypt
    # Will return the encrypted message and the MAC tag (hash value) of the message
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))

    return key, ciphertext, cipher_aes.nonce, tag


def aes_decrypt(aes_key, ciphertext, nonce, tag):
    # Create an AES object
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    # Decrypt the message
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_data.decode('utf-8')


def generate_rsa_keys(key_name, key_size=2048):
    # Generate a key-pair with the specified key size
    key = RSA.generate(key_size)

    # Extract the private key
    private_key = key.export_key()
    with open(f'./rsa_keys/{key_name}_private.pem', 'wb') as out_file:
        out_file.write(private_key)

    # Extract the public key
    public_key = key.public_key().export_key()
    with open(f'./rsa_keys/{key_name}_public.pem', 'wb') as out_file:
        out_file.write(public_key)


def rsa_encrypt(rsa_key_name, message):
    recipient_key = RSA.importKey(open(f'./rsa_keys/{rsa_key_name}.pem').read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.encrypt(message.encode('utf-8'))


def rsa_decrypt(cipher, recipient_key):
    if type(recipient_key) != RsaKey:
        if os.path.isfile(f'./rsa_keys/{recipient_key}.pem'):
            recipient_key = RSA.importKey(open(f'./rsa_keys/{recipient_key}.pem').read())
        else:
            print(f'No key file named {recipient_key}.pem found')
            return ""
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.decrypt(cipher).decode('utf-8')


def encrypt_message(message, recipient_rsa_key_name):
    # Encrypt the message using AES
    # Encrypt the generated AES key using RSA
    pass


def decrypt_message():
    # Decrypt the AES key using RSA
    # Decrypt the message using AES
    pass


def main():
    # aes_key, aes_cipher, aes_nonce, aes_tag = aes_encrypt('This is my super secret')
    # message = aes_decrypt(aes_key, aes_cipher, aes_nonce, aes_tag)
    # print(message)
    # generate_rsa_keys('bob')
    rsa_cipher = rsa_encrypt('carl_public', 'Dear Alice. Come to the pub tonight!')
    message = rsa_decrypt(rsa_cipher, 'carl_private')
    print(message)


if __name__ == '__main__':
    main()
