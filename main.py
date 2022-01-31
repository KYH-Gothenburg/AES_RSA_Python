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
    return cipher_rsa.encrypt(message)
    # return cipher_rsa.encrypt(message.encode('utf-8'))


def rsa_decrypt(cipher, recipient_key):
    if type(recipient_key) != RsaKey:
        if os.path.isfile(f'./rsa_keys/{recipient_key}.pem'):
            recipient_key = RSA.importKey(open(f'./rsa_keys/{recipient_key}.pem').read())
        else:
            print(f'No key file named {recipient_key}.pem found')
            return ""
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    return cipher_rsa.decrypt(cipher)
    # return cipher_rsa.decrypt(cipher).decode('utf-8')


def encrypt_message(message, recipient_rsa_key_name):
    # Encrypt the message using AES
    aes_key, aes_cipher, aes_nonce, aes_tag = aes_encrypt(message)

    # Encrypt the generated AES key using RSA
    encrypted_aes_key = rsa_encrypt(recipient_rsa_key_name, aes_key)

    return (encrypted_aes_key, aes_nonce, aes_tag, aes_cipher)


def decrypt_message(priv_key_name, encrypted_data):
    # Extract encrypted data
    encrypted_aes_key, aes_nonce, aes_tag, aes_cipher = encrypted_data
    # Decrypt the AES key using RSA
    aes_key = rsa_decrypt(encrypted_aes_key, priv_key_name)
    # Decrypt the message using AES
    plaintext = aes_decrypt(aes_key, aes_cipher, aes_nonce, aes_tag)
    return plaintext


def store_encrypted_data(filename, encrypted_data):
    with open(f'./encrypted_data/{filename}.bin', 'wb') as out_file:
        for data in encrypted_data:
            out_file.write(data)


def read_encrypted_data(filename, rsa_key_name):
    priv_rsa_key = RSA.importKey(open(f'./rsa_keys/{rsa_key_name}.pem').read())
    with open(f'./encrypted_data/{filename}.bin', 'rb') as in_file:
        aes_key, aes_nonce, aes_tag, ciphertext = \
            [in_file.read(data) for data in (priv_rsa_key.size_in_bytes(), 16, 16, -1)]
    return (aes_key, aes_nonce, aes_tag, ciphertext)

def main():
    # aes_key, aes_cipher, aes_nonce, aes_tag = aes_encrypt('This is my super secret')
    # message = aes_decrypt(aes_key, aes_cipher, aes_nonce, aes_tag)
    # print(message)
    # generate_rsa_keys('bob')
    # rsa_cipher = rsa_encrypt('carl_public', 'Dear Alice. Come to the pub tonight!')
    # message = rsa_decrypt(rsa_cipher, 'carl_private')
    # print(message)

    # Sender code
    print("Sender")
    message = input('Message to encrypt: ')
    recipient_key_name = input('Public key name of recipient: ')
    filename = input('Filename for encrypted data: ')
    encrypted_data = encrypt_message(message, recipient_key_name)
    store_encrypted_data(filename, encrypted_data)

    # Receiver code
    print("Receiver")
    priv_key = input('Private key name to be used for encryption: ')
    filename = input('Name of encrypted file: ')
    encrypted_data = read_encrypted_data(filename, priv_key)
    plaintext_message = decrypt_message(priv_key, encrypted_data)
    print(plaintext_message)



if __name__ == '__main__':
    main()
