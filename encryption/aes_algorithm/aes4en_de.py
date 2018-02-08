from Crypto.Cipher import AES
import hashlib

def get_md5(password):
    """encrypted password
    """
    md5 = hashlib.md5()
    md5.update((password + "gauss").encode('utf-8'))
    return md5.digest()



class AESED(object):
    def __init__(self, key):
        self.BLOCK_SIZE = 16
        self.key = key
        self.iv = self.key[:16]

    def encrypt(self, data):
        """Encrypt the data
        """
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        return aes.encrypt(self.pad(data)).hex()

    def decode(self, hex_data):
        """Decrypt the data
        """
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.unpad(aes.decrypt(bytes.fromhex(hex_data)))

    def pad(self, data):
        pad = self.BLOCK_SIZE - len(data) % self.BLOCK_SIZE
        return (data + pad * chr(pad)).encode('utf-8')

    def unpad(self, padded):
        return padded[:-padded[-1]]



if __name__ == '__main__':
    """
    example
    """
    password = "pass"
    aesed = AESED(get_md5(password))
    txt = "i am plain text"
    _en = aesed.encrypt(txt)
    _de = aesed.decode(_en)
    print("_en:", _en)
    print("_de:", _de)
