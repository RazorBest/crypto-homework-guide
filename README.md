# Guide for first homework of the cryptography course

This is an assigmnent for the cryptography course. We have to implement some chose ciphertext attacks in a client-server model.
We are given the source code of the server, server.py. If we look at it, the server gives us 2 options:
  - get a guest token
  - send a token and verify it

To understand this better, I drew the server-attacker model:

![Attacker model](/crypto_attacker_model1.png)

So, the attacker gets the guest token, which corresponds to the guest user. Then, it generates new tokens, sends them to the server and checks if the server responds with "fail" or "success".

The final purpose is to send a login token to the server such that it responds with "success". In reality, the success message contains a secret flag.
