"""Simple nested-encryption and onion-routing client for Lab Assignment I."""

import argparse
import json
import os
import threading
import time
from pathlib import Path

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BROKER = "51.94.164.150"
PORT = 1883
MQTT_USER = "sinf"
ID_SIZE = 5


def check_id(user_id):
    if not user_id or len(user_id.encode("ascii")) > ID_SIZE:
        raise ValueError("Use a user-id of at most five ASCII bytes.")


def rsa_oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def encrypt_layer(public_key, data):
    key = AESGCM.generate_key(bit_length=128)
    encrypted_key = public_key.encrypt(key, rsa_oaep())
    # The lab specifies that the AES-GCM nonce is the one-use AES key.
    encrypted_data = AESGCM(key).encrypt(key, data, None)
    return encrypted_key + encrypted_data


def decrypt_layer(private_key, packet):
    key_size = private_key.key_size // 8
    if len(packet) <= key_size:
        raise ValueError("Encrypted packet is incomplete.")
    key = private_key.decrypt(packet[:key_size], rsa_oaep())
    return AESGCM(key).decrypt(key, packet[key_size:], None)


def pack(next_hop, data):
    check_id(next_hop)
    return next_hop.encode("ascii").ljust(ID_SIZE, b"\0") + data


def unpack(data):
    if len(data) < ID_SIZE:
        raise ValueError("Decrypted layer is incomplete.")
    next_hop = data[:ID_SIZE].rstrip(b"\0").decode("ascii")
    check_id(next_hop)
    return next_hop, data[ID_SIZE:]


def read_public_key(user_id, directory):
    path = directory / f"{user_id}.pem"
    return serialization.load_pem_public_key(path.read_bytes())


def read_private_key(path):
    data = path.read_bytes()
    try:
        return serialization.load_pem_private_key(data, password=None)
    except ValueError:
        return serialization.load_ssh_private_key(data, password=None)


def make_packet(route, message, public_dir):
    """Build the packet from recipient to first relay (Algorithm 1)."""
    if len(route) < 2:
        raise ValueError("Route must contain the sender and a recipient.")
    for user_id in route:
        check_id(user_id)

    sender = route[0]
    recipient = route[-1]
    final_data = json.dumps([sender, message], ensure_ascii=False).encode("utf-8")
    packet = encrypt_layer(
        read_public_key(recipient, public_dir), pack("end", final_data)
    )

    # Add each intermediate relay layer, moving backwards along the route.
    for i in range(len(route) - 2, 0, -1):
        hop = route[i]
        next_hop = route[i + 1]
        packet = encrypt_layer(read_public_key(hop, public_dir), pack(next_hop, packet))
    return route[1], packet


def main():
    parser = argparse.ArgumentParser(description="Send or receive onion-routed messages.")
    parser.add_argument("--id", required=True, help="This participant's user-id")
    parser.add_argument("--private-key", type=Path, help="Private key file (needed to receive)")
    parser.add_argument("--public-dir", type=Path, default=Path("public_keys"))
    parser.add_argument("--send", help="Message to send")
    parser.add_argument("--route", nargs="+", help="Route: sender relay... recipient")
    parser.add_argument("--client-id", help="Optional MQTT connection ID")
    args = parser.parse_args()

    check_id(args.id)
    sending = args.send is not None
    if sending and (not args.route or args.route[0] != args.id):
        parser.error("For sending, --route must start with --id.")
    if not sending and args.private_key is None:
        parser.error("Receiving requires --private-key.")
    password = os.environ.get("MQTT_PASSWORD")
    if not password:
        parser.error("Set MQTT_PASSWORD to the course password before running.")

    private_key = read_private_key(args.private_key) if args.private_key else None
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=args.client_id or args.id,
        protocol=mqtt.MQTTv311,
    )
    client.username_pw_set(MQTT_USER, password)
    connected = threading.Event()
    rejected = threading.Event()

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code != 0:
            print(f"Broker refused the connection: {reason_code}")
            rejected.set()
        else:
            print(f"Connected to {BROKER}:{PORT}.")
            if private_key:
                client.subscribe(args.id)
                print(f"Listening on topic {args.id!r}.")
        connected.set()

    def on_message(client, userdata, packet):
        try:
            next_hop, data = unpack(decrypt_layer(private_key, packet.payload))
            if next_hop != "end":
                client.publish(next_hop, data, qos=1)
                print(f"Forwarded the encrypted packet to {next_hop!r}.")
            else:
                sender, message = json.loads(data.decode("utf-8"))
                print(f"end | sender={sender} | message={message}")
        except Exception as error:
            print(f"Could not process packet: {error}")

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER, PORT)
    client.loop_start()

    if not connected.wait(15) or rejected.is_set():
        client.loop_stop()
        client.disconnect()
        raise SystemExit("MQTT connection was not accepted.")

    if sending:
        first_hop, packet = make_packet(args.route, args.send, args.public_dir)
        client.publish(first_hop, packet, qos=1).wait_for_publish()
        print(f"Encrypted message sent to first relay {first_hop!r}.")
        client.disconnect()
        client.loop_stop()
    else:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            client.disconnect()
            client.loop_stop()
            print("Stopped.")


if __name__ == "__main__":
    main()
