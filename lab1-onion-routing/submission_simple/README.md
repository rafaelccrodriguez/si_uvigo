# Lab I — sending a message with onion routing

This program encrypts a message in layers and sends it through MQTT. Each
relay opens only its own layer and forwards the remaining packet to the next
user ID. Only the final recipient reads the message.

## 1. Where to put the keys

Run the commands from the main `InformationSecurity-Lab` directory. The
program looks for public keys at:

```text
public_keys/ID.pem
```

For example, the route `RAFA → ali → APB` needs these files:

```text
public_keys/ali.pem
public_keys/APB.pem
```

IDs and filenames are case-sensitive. Each participant keeps their private
key and uses it only on their own computer. Never send your private key to
another person.

## 2. Start the relays and recipient

Each participant on the route must run the program on their own computer and
leave it running. Use a separate terminal for each participant.

Example for ALI:

```bash
cd ~/InformationSecurity-Lab
source .venv/bin/activate
read -s "MQTT_PASSWORD?Course MQTT password: "
printf '\n'
export MQTT_PASSWORD
python submission_simple/onion_mqtt.py --id ali --private-key keys/ali
```

On APB's computer, use APB's ID and private-key file:

```bash
python submission_simple/onion_mqtt.py --id APB --private-key keys/APB
```

In a new terminal, repeat the first four setup commands to activate the
environment and enter the password. The password is hidden as you type.

## 3. Send a message from RAFA

In another terminal, prepare the environment and enter the password as above.
Then run:

```bash
python submission_simple/onion_mqtt.py --id RAFA --route RAFA ali APB --send "Hello, APB!"
```

The program reads `ali.pem` and `APB.pem`, builds the encrypted layers, and
publishes the packet to the first relay, `ali`. ALI forwards the encrypted
packet to APB.

## 4. Use a different route

Replace `ali` and `APB` with the IDs on your route. For each relay and the
recipient, put the matching public key in `public_keys/ID.pem` and ask that
participant to run the program with their own private key. The route can have
any number of relays.

The sender does not need their private key to send a message. This code follows
the lab's specified parameters: RSA-OAEP, AES-GCM, a 128-bit AES key, and the
one-use AES key as the nonce.
