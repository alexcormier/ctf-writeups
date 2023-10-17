# A Cipher Lost in Time

For this challenge, we're given a `flag.txt` file which seems to be encrypted:

```py
b'\x8c"Q6G\xa6\x03Up\x02\xa5\x02\xe9\x1ein\xe5\xed)\n\x06\xe8P\xdb\xdd\x9a^\x1fN\x1c\x84\xc0\xf6-\x93\x1f\xa3W\x1e\xd2'
```

We're also given a python script:

```py
import numpy as np

def encrypt(message, key):
    message_points = np.array([ord(char) for char in message])

    if message_points.shape[0] % key.shape[0] != 0:
        padding = key.shape[0] - (message_points.shape[0] % key.shape[0])
        message_points = np.concatenate([message_points, np.zeros(padding)])

    message_matrix = message_points.reshape((-1, key.shape[0])).T
    encoded_matrix = np.dot(key, message_matrix) % 251

    return bytearray(int(code) for code in encoded_matrix.T.flatten())
    
key = np.array([[n1, n2], [n3, n4]])
message = "FLAG:"+"HF-fakeflag"
encoded_message = encrypt(message, key)
print(encoded_message)
```

Evidently, we need to decrypt the flag that was encrypted with the provided algorithm. However, we don't have the decryption algorithm, nor do we have the key. We'll have to figure those out ourselves.

## The Decryption Algorithm

The encryption is rather simple. If we ignore type conversions and padding, it really just boils down to this one line:

```py
encoded_matrix = np.dot(key, message_matrix) % 251
```

This is a modular matrix multiplication. The decryption algorithm must then be a multiplication with the modular inverse of the key matrix, which we can compute like so:

```py
def inv_mod(A, n):
    '''Compute the modular inverse of A mod n'''
    det_A = int(det(A))
    inverse_det_A = pow(det_A, -1, n)
    adjugate_A = (inv(A) * det_A).astype(int)
    return (adjugate_A * inverse_det_A) % n
```

## The Key

Now that we have the decryption algorithm, we need a key to use with it. There are four important things to notice that will help us get that key:

1. the key is (only) 4 numbers: `key = np.array([[n1, n2], [n3, n4]])`;
1. the matrix multiplication is done mod 251 (which is pretty small);
1. we know the first 8 characters of the ciphertext: `FLAG:HF-`;
1. the encryption operates on pairs of characters, so changing e.g. the first plaintext characters only affects the first two cipher text characters.

Points 1 and 2 tell us that the key space is small: 251<sup>4</sup> ≈ 2<sup>32</sup> possibibilities. Points 3 and 4 give us a way to tell if a given key is correct.

So this challenge is now reduced to a brute-force exercise. We can encrypt `FLAG:HF-` with all possible keys until we get a result that matches the first 8 bytes of the given encrypted flag. We will then have recovered the key.

## The Flag

We have all the pieces of the puzzle now, so all that's left is putting them together and retrieving the plaintext flag:

```py
import numpy as np
from numpy.linalg import det, inv
from itertools import product

def inv_mod(A, n):
  '''Compute the modular inverse of A mod n'''
  det_A = int(det(A))
  inverse_det_A = pow(det_A, -1, n)
  adjugate_A = (inv(A) * det_A).astype(int)
  return (adjugate_A * inverse_det_A) % n

def create_matrix(message, key_shape):
    '''Create a matrix from a message for encryption with a key of the given shape'''
    message_points = np.array(message)
    if message_points.shape[0] % key_shape[0] != 0:
        padding = key_shape[0] - (message_points.shape[0] % key_shape[0])
        message_points = np.concatenate([message_points, np.zeros(padding)])
    return message_points.reshape((-1, key_shape[0])).T

def raw_crypt(message_matrix, key):
    '''Encrypts message_matrix with the given key'''
    encoded_matrix = np.dot(key, message_matrix) % 251
    return bytearray(int(code) for code in encoded_matrix.T.flatten())

def decrypt(encoded_message, key):
    '''Decrypt encoded_message with the given key'''
    inverse_key = inv_mod(key, 251)
    message_matrix = create_matrix(encoded_message, key.shape)
    return raw_crypt(message_matrix, inverse_key).decode()

ciphertext = bytearray(b'\x8c"Q6G\xa6\x03Up\x02\xa5\x02\xe9\x1ein\xe5\xed)\n\x06\xe8P\xdb\xdd\x9a^\x1fN\x1c\x84\xc0\xf6-\x93\x1f\xa3W\x1e\xd2')

# precompute some matrices to avoid doing it every loop iteration
ciphertext_matrix = create_matrix(ciphertext, (2, 2))
message_matrix = create_matrix([ord(char) for char in "FLAG:HF-"], (2, 2))

for n1, n2, n3, n4 in product(range(251), repeat = 4):
    key = np.array([[n1, n2], [n3, n4]])
    encoded_message = raw_crypt(message_matrix, key)
    if encoded_message[:8] == ciphertext[:8]:
        print(decrypt(ciphertext, key))
        exit(0)
```

After running for a little while, the above script will spit out this little gem: `FLAG:HF-e897206a0575e67154c83a9a4d77b02e`.
