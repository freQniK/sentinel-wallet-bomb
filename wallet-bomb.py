from keyrings.cryptfile.cryptfile import CryptFileKeyring
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins
import ecdsa
import hashlib
import bech32
from faker import Faker
import pwd
import os
from os import path

KEYRINGDIR = '/home/' + str(pwd.getpwuid(os.getuid())[0]) + '/.dvpn-wallet-bomb'
PASSPHRASE = "I65h/1gXwwGcAoOe0e+de0GiwMQLX/vYztAKjQf11DM"
def __keyring(keyring_passphrase: str):
        kr = CryptFileKeyring()
        kr.filename = "keyring.cfg"
        kr.file_path = path.join(KEYRINGDIR, kr.filename)
        kr.keyring_key = keyring_passphrase
        return kr

def create(wallet_name, keyring_passphrase, seed_phrase = None):
    # Credtis: https://github.com/ctrl-Felix/mospy/blob/master/src/mospy/utils.py

    if seed_phrase is None:
        seed_phrase = Mnemonic("english").generate(strength=256)

    #print(seed_phrase)  # TODO: only-4-debug
    seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
    bip44_def_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.COSMOS).DeriveDefaultPath()

    privkey_obj = ecdsa.SigningKey.from_string(bip44_def_ctx.PrivateKey().Raw().ToBytes(), curve=ecdsa.SECP256k1)
    pubkey  = privkey_obj.get_verifying_key()
    s = hashlib.new("sha256", pubkey.to_string("compressed")).digest()
    r = hashlib.new("ripemd160", s).digest()
    five_bit_r = bech32.convertbits(r, 8, 5)
    account_address = bech32.bech32_encode("sent", five_bit_r)
    #print(account_address)

    # Create a class of separated method for keyring please
    kr = __keyring(keyring_passphrase)
    kr.set_password("dvpn-wallet-bomb", wallet_name, bip44_def_ctx.PrivateKey().Raw().ToBytes().hex())

    return {
        'address': account_address,
        'seed': seed_phrase
    }
    
    
if __name__ == "__main__":
    fake = Faker()
    
    wallet_bomb_file = open("wallet_bomb.txt", "a+")
    
    for _ in range(10):
        wallet_name = fake.name()
        wallet = create(wallet_name, PASSPHRASE)
        print(f"Wallet Name: {wallet_name}\n\nSeed Phrase:\n{wallet['seed']}\n\nAddress: {wallet['address']}")
        wallet_bomb_file.write(f"Wallet Name: {wallet_name}\n\nSeed Phrase:\n{wallet['seed']}\n\nAddress: {wallet['address']}\n\n")
