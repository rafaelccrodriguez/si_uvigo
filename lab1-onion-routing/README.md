# Assignment I: nested hybrid encryption and onion routing

This folder follows the professor's Algorithms 1 and 2 without replacing their
cryptographic choices.  Work through it in this order.

## 1. What you are building

Choose a 3-4 letter user-id (the PDF allows at most five bytes).  A route has
the form:

```text
source -> relay 1 -> relay 2 -> recipient
```

For example, `demo -> rly1 -> rly2 -> dest`.  The sender creates the innermost
layer for the recipient first:

```text
Encrypt(pk_dest, (end, (sender, message)))
```

Then it wraps that packet once for each relay, moving backwards through the
route.  The layer for `rly2` says only `next hop = dest`; the layer for `rly1`
says only `next hop = rly2`.  That is the “onion”.

Every hybrid-encryption layer is sent as binary bytes:

```text
RSA-OAEP(AES-128 key) || AES-GCM(ciphertext + authentication tag)
```

Within the AES-GCM plaintext, the first five bytes hold the next user-id,
padded with zero bytes.  The rest is the next encrypted packet (or, at the
final node, a small UTF-8 JSON pair containing sender and message).  Thus a
relay can learn only its next hop; it cannot decrypt the next packet.

The PDF explicitly specifies `iv`/nonce = the random 128-bit AES key.  The
code deliberately follows that lab requirement.  It is not a general-purpose
AES-GCM pattern to copy into other applications.

## 2. Install and run the local test first

From this folder:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest -v
python local_demo.py
```

The test creates temporary keys, sends `demo -> rly1 -> rly2 -> dest`, checks
that each relay sees the right next hop, and checks that AES-GCM rejects a
modified packet.  It never contacts MQTT.

## 3. Create your real assignment key pair

The assignment asks for `ssh-keygen`.  This creates a 2048-bit RSA private key
in PEM format and a normal SSH public-key file:

```bash
mkdir -p keys public_keys
ssh-keygen -t rsa -b 2048 -m PEM -f keys/yourid -N ''
openssl rsa -in keys/yourid -pubout -out public_keys/yourid.pem
```

Tell the instructor your chosen `yourid` and the public key requested by the
course.  Put every classmate public key in `public_keys/<user-id>.pem`.  Do not
share anything in `keys/`.

## 4. Before MQTT: questions to answer in your own words

1. At `rly1`, why can it forward to `rly2` but not read the message?
2. Why does only `dest` see the `end` marker?
3. Why does each layer need a new random AES key?

## 5. MQTT is the final transport step

The course PDF gives the broker IP `51.94.164.150`, user `sinf`, and says that
the password is on the course website. `mqtt_node.py` subscribes to the topic
named by the local user-id, applies `decode_or_relay`, and publishes the
remaining opaque packet to `next_hop`. Do not put the course password in source
code; it is read from an environment variable.

In separate terminals, relays/recipient run:

```bash
export MQTT_PASSWORD='the password from the course site'
python mqtt_node.py --id rly1 --private-key keys/rly1 --public-dir public_keys
python mqtt_node.py --id rly2 --private-key keys/rly2 --public-dir public_keys
python mqtt_node.py --id dest --private-key keys/dest --public-dir public_keys
```

The sender publishes one message (and does not need its private key for that
action):

```bash
export MQTT_PASSWORD='the password from the course site'
python mqtt_node.py --id demo --public-dir public_keys \
  --route demo rly1 rly2 dest --send 'Olá para a turma'
```

In the real class replace the example ids with the instructor-provided key
directory and your agreed route. MQTT only transports opaque bytes: `rly1` and
`rly2` print the next hop, whereas `dest` prints `end`, sender, and message.
