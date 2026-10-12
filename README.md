# Information Security Labs — University of Vigo

This repository contains my coursework for the Information Security course.

## Lab 1 — Onion routing

The `lab1-onion-routing/` folder contains a minimal MQTT implementation of nested hybrid encryption, a local demo, and the protocol test. Start with its README. The `submission_simple/` subfolder contains the simplified submission version.

## Lab 2 — Verifiable Secret Sharing

The `lab2-vss/` folder contains a small Python demo using KZG commitments: `dealer.py` creates shares and witnesses, and `client.py` verifies shares and reconstructs the secret. Start with its README.

## Keep local secrets out of Git

Private keys, classmates' public-key files, MQTT credentials, virtual environments, and generated share files are not part of this repository. The `.gitignore` excludes common local copies of these files.
