"""MQTT transport for the Assignment I onion protocol.

Start one copy for each participant/relay.  Messages published to a topic named
after the user-id are binary onion packets, never plaintext.
"""

import argparse
import os
from pathlib import Path

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import serialization

from onion_protocol import Delivered, Forward, build_onion, decode_or_relay, validate_user_id


DEFAULT_BROKER = "51.94.164.150"  # The IP stated in the assignment PDF.


def load_private_key(path: Path):
    raw = path.read_bytes()
    try:
        return serialization.load_pem_private_key(raw, password=None)
    except ValueError:
        return serialization.load_ssh_private_key(raw, password=None)


def load_public_key(path: Path):
    raw = path.read_bytes()
    try:
        return serialization.load_pem_public_key(raw)
    except ValueError:
        return serialization.load_ssh_public_key(raw)


def public_keys_for(route, directory: Path):
    keys = {}
    # The source key is not used to construct this packet.
    for user_id in route[1:]:
        candidates = (directory / f"{user_id}.pem", directory / f"{user_id}.pub")
        for candidate in candidates:
            if candidate.exists():
                keys[user_id] = load_public_key(candidate)
                break
        else:
            raise FileNotFoundError(f"No public key for {user_id!r}; expected {candidates[0]} or {candidates[1]}.")
    return keys


def main() -> None:
    parser = argparse.ArgumentParser(description="MQTT node for Assignment I")
    parser.add_argument("--id", required=True, dest="user_id", help="This node's 3-4 letter user-id")
    parser.add_argument("--private-key", type=Path, help="Private key PEM/OpenSSH file; needed to receive")
    parser.add_argument("--public-dir", type=Path, default=Path("public_keys"))
    parser.add_argument("--broker", default=DEFAULT_BROKER)
    parser.add_argument("--port", default=1883, type=int)
    parser.add_argument("--send", metavar="MESSAGE", help="Build and publish an onion packet")
    parser.add_argument("--route", nargs="+", help="Route: source relay... recipient; required with --send")
    args = parser.parse_args()

    validate_user_id(args.user_id)
    if args.send is not None and not args.route:
        parser.error("--send requires --route")
    if args.send is None and args.private_key is None:
        parser.error("Receiving requires --private-key")
    if args.route and args.route[0] != args.user_id:
        parser.error("The route must start with --id")

    password = os.environ.get("MQTT_PASSWORD")
    if not password:
        parser.error("Set MQTT_PASSWORD to the course password before connecting.")
    private_key = load_private_key(args.private_key) if args.private_key else None

    client = mqtt.Client(client_id=f"onion-{args.user_id}", protocol=mqtt.MQTTv311)
    client.username_pw_set("sinf", password)

    def on_connect(client, userdata, flags, reason_code):
        if reason_code != 0:
            raise RuntimeError(f"MQTT connection failed: {reason_code}")
        if private_key is not None:
            client.subscribe(args.user_id)
            print(f"Listening for encrypted packets on topic {args.user_id!r}.")

    def on_message(client, userdata, message):
        try:
            result = decode_or_relay(private_key, message.payload)
            if isinstance(result, Forward):
                client.publish(result.next_hop, result.packet, qos=1)
                print(f"Relayed an opaque packet to {result.next_hop!r}.")
            else:
                assert isinstance(result, Delivered)
                print(f"end | sender={result.sender} | message={result.message}")
        except Exception as exc:
            # A malformed/tampered packet is deliberately not forwarded.
            print(f"Rejected packet on {args.user_id!r}: {exc}")

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(args.broker, args.port)
    client.loop_start()

    if args.send is not None:
        keys = public_keys_for(args.route, args.public_dir)
        first_hop, packet = build_onion(args.route, keys, args.user_id, args.send)
        info = client.publish(first_hop, packet, qos=1)
        info.wait_for_publish()
        print(f"Published encrypted onion packet to {first_hop!r}.")

    try:
        # A sender exits after its publish; a relay/recipient keeps listening.
        if args.send is None:
            while True:
                __import__("time").sleep(1)
    except KeyboardInterrupt:
        print("Stopping.")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
