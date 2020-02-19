import random
from sys import byteorder

def gen_rand_bytes(length=1):
    ''' Generage a randomb byte array
    '''
    x = random.getrandbits(8 * length)
    return x.to_bytes(length, byteorder)    

def test_gen_rand_bytes():
    for x in [1,10,100,76]:
        assert x == len(gen_rand_bytes(x))
        
def secret_split(secret, ways=2):
    secret = secret.encode()
    length = len(secret)
    keys = []
    for i in range(ways - 1):
        keys.append(gen_rand_bytes(length))
        secret =  bytes(a^b for a,b in zip(secret, keys[i]))
    keys.append(secret)
    return keys
        
def secret_unsplit(keys):
    secret = keys[0]
    for k in keys[1:]:
        secret = bytes(a^b for a,b in zip(secret, k))
    return secret.decode()

def test_secret_split():
    assert secret_unsplit(secret_split('This is a secret'))
    assert secret_unsplit(secret_split('This is a secret',10))

def bit_commit(message):
    ''' Using one-way function'''
    message = message.encode()
    R1, R2 = gen_rand_bytes(16), gen_rand_bytes(16)
    True

def bit_commit_verify(R1, R2, message, hashed):
    pass
    
def test_bit_commit():
    hashed, R1
    
if __name__ == '__main__':
    test_gen_rand_bytes()
    test_secret_split()
    keys = secret_split('This is a secret!',5)
    print(secret_unsplit(keys))
    
    
    
    