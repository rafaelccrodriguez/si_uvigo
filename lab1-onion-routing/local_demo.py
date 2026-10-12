"""A no-network, four-node execution of Algorithms 1 and 2."""

from cryptography.hazmat.primitives.asymmetric import rsa

from onion_protocol import Delivered, Forward, build_onion, decode_or_relay


def main() -> None:
    route = ["demo", "rly1", "rly2", "dest"]
    private_keys = {
        user_id: rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for user_id in route
    }
    public_keys = {user_id: key.public_key() for user_id, key in private_keys.items()}

    first_hop, packet = build_onion(route, public_keys, "demo", "Mensagem de teste")
    current_hop = first_hop
    print(f"Sender: publicou ciphertext para {current_hop!r}.")

    while True:
        result = decode_or_relay(private_keys[current_hop], packet)
        if isinstance(result, Forward):
            # This is all an intermediate node needs to know.
            print(f"{current_hop}: removeu uma camada; encaminha para {result.next_hop!r}.")
            current_hop, packet = result.next_hop, result.packet
            continue
        assert isinstance(result, Delivered)
        print(f"{current_hop}: end | sender={result.sender!r} | message={result.message!r}")
        break


if __name__ == "__main__":
    main()
