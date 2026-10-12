# Lab II — Verifiable Secret Sharing

Install the dependency in a Python environment with `python -m pip install -r requirements.txt`.
The provided `trusted_setup.txt` must stay beside both programs.

Create a demo sharing with five participants and threshold two:

```bash
python dealer.py
```

The dealer writes the commitment, five shares, and their KZG witnesses to
`shares.json`. The example secret is 123. A different integer secret can be
selected with `--secret`.

Verify the shares and reconstruct the secret:

```bash
python client.py
```

At least `t + 1` valid shares are needed, and the parameters must satisfy
`n >= 2t + 1`. The JSON file is a simple local simulation of sharing; it is
not a private channel for distributing individual shares to real participants.
