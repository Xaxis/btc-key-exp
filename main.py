import os
import csv
import time
import requests
import ecdsa
import hashlib
import base58

CSV_FILENAME = "addresses.csv"

def generate_private_key() -> bytes:
    """
    Generates a new 32-byte (256-bit) random private key.
    Returns the raw bytes.
    """
    return os.urandom(32)

def private_key_to_public_key(private_key: bytes, compressed: bool = True) -> bytes:
    """
    Takes a 32-byte private key, performs EC multiplication on secp256k1,
    and returns the public key in either compressed or uncompressed format.
    """
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()

    if not compressed:
        # Uncompressed pubkey format: 0x04 + X + Y (65 bytes total)
        return b'\x04' + vk.to_string()
    else:
        # Compressed pubkey format: 0x02 or 0x03 + X (33 bytes total)
        # If Y is even, use 0x02; if odd, use 0x03
        x_coordinate = vk.pubkey.point.x()
        y_coordinate = vk.pubkey.point.y()
        prefix = b'\x02' if (y_coordinate % 2 == 0) else b'\x03'
        return prefix + x_coordinate.to_bytes(32, 'big')

def hash160(data: bytes) -> bytes:
    """
    Returns RIPEMD-160(SHA-256(data)).
    """
    sha = hashlib.sha256(data).digest()
    h160 = hashlib.new('ripemd160')
    h160.update(sha)
    return h160.digest()

def public_key_to_p2pkh_address(public_key: bytes, mainnet: bool = True) -> str:
    """
    Converts a public key (compressed or uncompressed) into a
    Base58Check-encoded P2PKH Bitcoin address.
    """
    # 1) HASH160: RIPEMD160(SHA256(public_key))
    pk_hash = hash160(public_key)

    # 2) Prepend version byte (0x00 for mainnet, 0x6f for testnet)
    version_byte = b'\x00' if mainnet else b'\x6f'
    payload = version_byte + pk_hash

    # 3) Double-SHA256 to get checksum
    checksum_full = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    checksum = checksum_full[:4]

    # 4) Append the checksum
    address_bytes = payload + checksum

    # 5) Base58Check-encode
    return base58.b58encode(address_bytes).decode('utf-8')

def get_balance_blockstream(address: str) -> int:
    """
    Returns the confirmed balance (in satoshis) for the given Bitcoin address
    using the Blockstream explorer API (mainnet).
    """
    url = f"https://blockstream.info/api/address/{address}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        # data["chain_stats"] contains the confirmed totals on-chain
        # "funded_txo_sum" is the total amount ever received,
        # "spent_txo_sum" is the total amount ever spent.
        # Balance in satoshis = funded_txo_sum - spent_txo_sum
        funded = data["chain_stats"]["funded_txo_sum"]
        spent = data["chain_stats"]["spent_txo_sum"]
        balance = funded - spent

        return balance

    except requests.exceptions.RequestException as e:
        print(f"Error fetching balance for {address}: {e}")
        return 0

def main():
    # Check if CSV file already exists:
    file_exists = os.path.isfile(CSV_FILENAME)

    try:
        # Open the CSV file once, in "append" mode
        with open(CSV_FILENAME, "a", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)

            # If file is new, write a header row
            if not file_exists:
                writer.writerow(["private_key_hex", "public_key_hex", "bitcoin_address", "balance_sats", "balance_btc"])

            while True:
                # 1) Generate a random private key
                private_key = generate_private_key()
                # 2) Convert private key to a compressed public key
                public_key = private_key_to_public_key(private_key, compressed=True)
                # 3) Convert public key to a mainnet P2PKH address
                btc_address = public_key_to_p2pkh_address(public_key, mainnet=True)
                # 4) Fetch balance (in satoshis)
                balance_sats = get_balance_blockstream(btc_address)
                balance_btc = balance_sats / 1e8

                # Print info to console
                print("Private Key (hex)  :", private_key.hex())
                print("Public Key (hex)   :", public_key.hex())
                print("Bitcoin Address    :", btc_address)
                print("Balance (sats)     :", balance_sats)
                print("Balance (BTC)      :", balance_btc)
                print("--------------------------------------------------")

                # Append this data to the CSV file
                writer.writerow([
                    private_key.hex(),
                    public_key.hex(),
                    btc_address,
                    balance_sats,
                    balance_btc
                ])

                # Sleep for a moment so as not to spam the API too quickly
                time.sleep(1)

    except KeyboardInterrupt:
        print("\nScript terminated by user.")

if __name__ == "__main__":
    main()
