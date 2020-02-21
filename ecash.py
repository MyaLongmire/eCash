from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import KeySerializationEncryption

import pickle
import random
import hashlib
import fractions

n = 10
r = random.sample(range(0,10),9)

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
public_key = _private_key.public_key()

# private_key = _private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, KeySerializationEncryption())
# private_key = long(private_key.encode('hex'), 16)
# 
# public_key = _public_key.public_bytes(Encoding.DER, PublicFormat.PKCS1)
# public_key = long(public_key.encode('hex'), 16)


#check for duplication
def dupchck(data):
    status = 'verfied'

    for i in r:
        if i + 1 in r:
            y = str(data[i + 1])
            x = str(data[i])

            if x[-13:-11] == y[-13:-11]:
                status = 'rej'
                break

        elif i - 1 in r:
            y = str(data[i - 1])
            x = str(data[i])

            if x[-13:-11] == y[-13:-11]:
                status = 'rej'
                break

        elif x + 2 in r:
            y = str(data[i + 2])
            x = str(data[i])

            if x[-13:-11] == y[-13:-11]:
                status = 'rej'
                break


    return status

#verification from bank to make sure all amounts are matching
def a_verify(data, quantity):
    status = 'verfied'

    for i in r:
        j = str(data[i])

        if j[-10:] != quantity:
            status = 'rej'

    return status


#id hashing for privacy
def h_id(ssn_l, ssn_r):
    id_f = ""
    id_r = {}
    id_l = {}

    for i in range (0,4):
        id_r[i] = int(hashlib.sha1(str(ssn_r[i])).hexdigest(), 16) % (10 ** 8)
        id_l[i] = int(hashlib.sha1(str(ssn_l[i])).hexdigest(), 16) % (10 ** 8)
        id_f = str(id_f) + str(id_l[i]) + str(id_r[i])

    return id_f

#determines factors for hiding
def f_hide(i):
    rand = int(random.random() * (i - 1))

    while(fractions.gcd(rand, i) != 1):
        rand = rand + 1

    return rand

#show signed message
def show(message, status, public_key):
    hidden_msg = int(message)
    #final = (hidden_msg * calc_inv(public_key[1], status)) % public_key[1]
    final = (hidden_msg * calc_inv(public_key[1], status)) % public_key[1]
    return str(final)

#bank verifying for merchant
def verify(message, public_key):
    return str(pow(int(message), * public_key) % public_key[1])

#customer side programming to generate m_ids and blindfactors file
def c_order():
    b_order = {}
    factor = {}

    while True:
        try:
            user_ssn = int(input("enter you ssn (9 digits): \t"))

        except ValueError:
            print("should only be numbers")
            continue

        if len(str(user_ssn)) > 9:
            print('too many digits\n')
            continue

        elif len(str(user_ssn)) < 9:
            print('not enough digits\n')
            continue

        else:
            break

    quantity = int(input("enter money order amount: \t"))
    q = str(quantity).rjust(10, '0')

    ssn_l, ssn_r = split_ssn(user_ssn)

    id_f = h_id(ssn_l, ssn_r)
    order = m_id(id_f, q , n)

    for i in range(0,n):
        b_order[i], factor[i] = hide(order[i], public_key)

    with open('f_hide', 'wb') as f:
        pickle.dump(factor, f)

    with open('m_ids', 'wb') as f:
        pickle.dump(b_order, f)

    print("orders saved and generated, waiting on bank\n")

#verify orders for merchant
def m_verify():
    status = 'verfied'

    with open('shown and signed orders', 'rb') as f:
        o_recieved = pickle.load(f)

    o_verify = verify(o_recieved, public_key)

    quantity = int(input("enter money order amount: \t"))
    q = str(quantity).rjust(10, '0')

    if o_verify[-10:] == q:
        print("verified by merchant - depositing to bank\n")

        with open('received', 'wb') as f:
            pickle.dump(o_verify, f)

        with open('verified', 'rb') as f:
            data_b = pickle.load(f)

        for i in r:
            x = str(data_b[i])
            y = str(o_verify)

            if y[-13:-11] == x[-13:-11]:
                status = 'rej'
                break
    else:
        status = 'rej'

    return status

#split ssn into XOR vars
def split_ssn(user_ssn):
    ssn_r = {}
    ssn_l = {}

    for i in range(0,4):
        ssn_l[i] = random.randrange(100)
        ssn_r[i] = ssn_l[i] ^ user_ssn

    with open('val_r', 'wb') as f:
        pickle.dump(ssn_r, f)

    with open('val_l', 'wb') as f:
        pickle.dump(ssn_l, f)

    return ssn_l, ssn_r

#sign hidden msg
def b_sig(message, private_key):
    return str(pow(int(message), *private_key))

#bank signing
def b_verify():
    o_verified = {}
    m_signed = {}
    m_show = {}

    print("bank is verifying\n")

    quantity = int(input("enter order amount: \t"))
    q = str(quantity).rjust(10, '0')

    with open('m_ids', 'rb') as f:
        b_order = pickle.load(f)

    with open('f_hide', 'rb') as f:
        factor = pickle.load(f)

    for i in r:
        m_signed[i] = b_sig(b_order[i], private_key)
        m_show[i] = show(m_signed[i], factor[i], public_key)
        o_verified[i] = verify(m_show[i], public_key)

    status = a_verify(o_verified, q)

    if status == 'verfied':
        print("done checking")

        status = dupchck(o_verified)

        if status == 'verfied':
            with open('verified', 'wb') as f:
                pickle.dump(o_verified, f)

    for j in range(0,10):
        if j not in r:
            m_signed = b_sig(b_order[j], private_key)

            with open('signed blinded order', 'wb') as f:
                pickle.dump(m_signed, f)

            print("done dublicating\n")

            return j
    else :
        return 'rej'

#find facotors to show
def calc_inv(m, val):
    i = 0
    j = 1
    x = m
    y = val

    while y:
        x, q, y = y, x // y, x % y
        i, j = j - q * i, i

    end = (1 - j * m) // val

    if end < 0:
        end += m

    assert 0 <= end < m and val * end % m == 1

    return end

#show customer
def c_show(x):
    with open('signed blinded order', 'rb') as f:
        sb_order = pickle.load(f)

    with open('f_hide', 'rb') as f:
        factor = pickle.load(f)

    show_order = show(sb_order, factor[x], public_key)

    with open('shown and signed orders', 'wb') as f:
        pickle.dump(show_order, f)

#hide msg
def hide(message, public_key):
    factor = f_hide(public_key[1])
    msg = int(message)
    hide_msg = (pow(factor, *public_key)*msg) % public_key[1]

    return hide_msg, factor

#N orders with rand IDs
def m_id(id_f, quantity, n):
    order = {}
    rand = random.sample(range(100,999),n)

    for i in range (0,n):
        order[i] = str(id_f) + str(rand[i]) + str(quantity)

    return order


def main():
    print("welcome to ecash\n")

    print(public_key)
    global n
    global n
    global n
    global r

    c_order()
    v = b_verify()

    if v != 'rej':
        print("The bank signed and verified the money order " +
              str(v) +
              "\n sending to merchant\n")
        c_show(v)
        m = m_verify()

        if m == 'rej':
            print("Could not be verified by merchant.\n")

    else:
        print("Could not be verified by the bank.\n")


if __name__ == "__main__":
    main()
