from ecdsa import SigningKey, SECP256k1
import os
import sha3


def privateKey2publicKey(private_key_string):
    """from private key produces the public key.
    """
    sk = SigningKey.from_string(bytes().fromhex(private_key_string), curve=SECP256k1)
    vk = sk.get_verifying_key()
    return vk.to_string().hex()

def publicKey2address(public_key):
    """generate the address from the public key.
    """
    sha3256 = sha3.keccak_256(bytes().fromhex(public_key)).hexdigest()
    return '0x' + sha3256[-40:]


if __name__ == '__main__':
    private_key = os.urandom(32).hex()
    public_key = privateKey2publicKey(private_key)
    address = publicKey2address(public_key)
    print("your private key :", private_key)
    print("your public key :", public_key)
    print("your address :", address)