# Guide for the first homework of the cryptography course

This is an assigmnent for the cryptography course. We have to implement some chose ciphertext attacks in a client-server model.
We are given the source code of the server, server.py. If we look at it, the server gives us 2 options:
  - get a guest token
  - send a token and verify it

To understand this better, I drew the server-attacker model:

![Attacker model](/crypto_attacker_model1.png)

So, the attacker gets the guest token, which corresponds to the guest user. Then, it generates new tokens, sends them to the server and checks if the server responds with "fail" or "success".

The final purpose is to send a login token to the server such that it responds with "success". In reality, the success message contains a secret flag.

Most of the time, the server will respond with a fail message:

![Server sends a fail message](/crypto_attacker2_fail.drawio.png)

The attacker wants the server to send a success message. If this happens, the attack will be over.
![Server sends a success message](/crypto_attacker2_success.png)

## A depper look into how the token is computed

In order to build an attack, we have to understand how the server encrypts the data. And see if the encryption protocol has a flaw.

The python source code related to how the token is built, looks like this:
```python
def encrypt(self, plain):
        rnd = self.C.encrypt(self.IV)
        cipher = byte_xor(plain, rnd) + SERVER_PUBLIC_BANNER + self.getIntegrity(plain)
        return cipher
```

We'll say that our token is the cipher. As you can see, the token is made out of 3 parts:
  - the ecnrypted plaintext
  - a fixed public banner
  - an integrity tag
