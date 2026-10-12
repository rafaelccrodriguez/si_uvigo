"""Protocol helpers that follow Algorithms 1 and 2 from Assignment I ToR.

The MQTT payload is binary.  A packet is ``RSA-OAEP(AES key) || AES-GCM data``.
Since all assignment RSA keys are 2048 bit, the first component is 256 bytes;
the decrypting private key also tells us that length, so no extra length field is
needed.  Inside AES-GCM, the first five bytes always encode the next user-id.
"""

import json
from dataclasses import dataclass
from typing import Dict, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ID_BYTES = 5
END_MARKER = "end"


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def validate_user_id(user_id: str) -> None:
    encoded = user_id.encode("ascii")
    if not 1 <= len(encoded) <= ID_BYTES:
        raise ValueError("A user-id must be 1 to 5 ASCII bytes (use 3-4 letters in this lab).")


def pack_next_hop(next_hop: str, remainder: bytes) -> bytes:
    """Represent (next-hop, remainder); its first five bytes hold next-hop."""
    validate_user_id(next_hop)
    return next_hop.encode("ascii").ljust(ID_BYTES, b"\0") + remainder


def unpack_next_hop(data: bytes) -> Tuple[str, bytes]:
    if len(data) < ID_BYTES:
        raise ValueError("Decrypted payload is shorter than the 5-byte next-hop field.")
    field, remainder = data[:ID_BYTES], data[ID_BYTES:]
    try:
        next_hop = field.rstrip(b"\0").decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("Next-hop field is not ASCII.") from exc
    validate_user_id(next_hop)
    return next_hop, remainder


def encrypt(public_key, plaintext: bytes) -> bytes:
    """Algorithm 1's Encrypt(pk, bytes), including its specified AES-GCM nonce."""
    aes_key = AESGCM.generate_key(bit_length=128)
    encrypted_key = public_key.encrypt(aes_key, _oaep())

    # Assignment I explicitly requires iv/nonce = k.  Keep this for the lab;
    # real protocols normally create a separate nonce according to their design.
    encrypted_data = AESGCM(aes_key).encrypt(aes_key, plaintext, None)
    return encrypted_key + encrypted_data


def decrypt(private_key, packet: bytes) -> bytes:
    """Reverse a single hybrid-encryption layer."""
    encrypted_key_size = private_key.key_size // 8
    if len(packet) <= encrypted_key_size:
        raise ValueError("Packet does not contain both RSA-OAEP and AES-GCM components.")
    encrypted_key, encrypted_data = packet[:encrypted_key_size], packet[encrypted_key_size:]
    aes_key = private_key.decrypt(encrypted_key, _oaep())
    return AESGCM(aes_key).decrypt(aes_key, encrypted_data, None)


def _encode_final(sender: str, message: str) -> bytes:
    validate_user_id(sender)
    return json.dumps([sender, message], ensure_ascii=False).encode("utf-8")


def _decode_final(data: bytes) -> Tuple[str, str]:
    try:
        sender, message = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Final payload is not a valid (sender, message) pair.") from exc
    if not isinstance(sender, str) or not isinstance(message, str):
        raise ValueError("Final payload must contain string sender and message values.")
    validate_user_id(sender)
    return sender, message


def build_onion(route, public_keys: Dict[str, object], sender: str, message: str) -> Tuple[str, bytes]:
    """Apply Algorithm 1 and return (first_relay, ciphertext_to_publish)."""
    if len(route) < 2:
        raise ValueError("Route must contain source and recipient, and usually one or more relays.")
    if route[0] != sender:
        raise ValueError("The route must start with the sender user-id.")
    # Algorithm 1 encrypts for h_1 ... h_n, never for source s itself.
    for user_id in route[1:]:
        validate_user_id(user_id)
        if user_id not in public_keys:
            raise KeyError(f"Missing public key for {user_id!r}.")

    recipient = route[-1]
    # m' = (end, (sender, message)); recipient learns forwarding has ended only here.
    packet = encrypt(public_keys[recipient], pack_next_hop(END_MARKER, _encode_final(sender, message)))
    for position in range(len(route) - 2, 0, -1):
        hop, next_hop = route[position], route[position + 1]
        packet = encrypt(public_keys[hop], pack_next_hop(next_hop, packet))
    return route[1], packet


@dataclass(frozen=True)
class Forward:
    next_hop: str
    packet: bytes


@dataclass(frozen=True)
class Delivered:
    sender: str
    message: str


def decode_or_relay(private_key, packet: bytes):
    """Apply Algorithm 2 at the node owning ``private_key``."""
    next_hop, remainder = unpack_next_hop(decrypt(private_key, packet))
    if next_hop != END_MARKER:
        return Forward(next_hop=next_hop, packet=remainder)
    sender, message = _decode_final(remainder)
    return Delivered(sender=sender, message=message)
