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
It is an encrypt function, that receives a plaintext and returns the ciphertext. In our case, the plaintext is a username.

We'll say that our token is the cipher. As you can see, the token is made out of 3 parts:
  - the ecnrypted plaintext
  - a fixed public banner
  - an integrity tag
  
![The internals of the identity token](/secret_token_form.drawio.png)

From e general perspective, the scheme is made such that:
   - generate a unique, secret token for a user
   - a user can request a token corresponding to its username
   - a user can send back the token to prove their identity
   - **a user can't generate a token for another user**

We want to somehow break the last checkpoint. 

## How does the server verify the token

Looking at the drawn attacker model, we see that the server receives a login/identity token from the attacker. Then it verifies it. If it returns true, the server will return "success". So in order to see how we can break the scheme, we need to understand the internals of the verification.

The verification in server.py depends on the decrypt function, that receives a token:
```python
def decrypt(self, input):
        rnd = self.C.encrypt(self.IV)
        secret_len = INTEGRITY_LEN + len(SERVER_PUBLIC_BANNER)
        cipher, secret, tag = input[:-secret_len], input[-secret_len:-INTEGRITY_LEN], input[-INTEGRITY_LEN:]
        plain = byte_xor(cipher, rnd)
        if secret != SERVER_PUBLIC_BANNER:
            return -1
        if self.getIntegrity(plain) != tag:
            return None
 
        return plain
```

We'll look at weaker versions of the scheme, first, and see if we can break them.

## Identity token scheme without encryption
The simplest scheme is just to send the unencrypted username:
```python
def encrypt(self, plain):
        cipher = plain
        return plain
```
