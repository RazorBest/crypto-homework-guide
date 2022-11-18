# Guide for first homework of the cryptography course

This is an assigmnent for the cryptography course. We have to implement some chose ciphertext attacks in a client-server model.
We are given the source code of the server, server.py. If we look at it, the server gives us 2 options:
  - get a guest token
  - send a token and verify it

To understand this better, I drew the server-attacker model:

![Attacker model](/img/export.png)
