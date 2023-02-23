import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()

public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
message = "Alô Mundo!"


receive_pk_b = requests.get('http://flask:5000/send-public-key').text.encode()
public_key_b = serialization.load_pem_public_key(receive_pk_b)
    

cipher_text = public_key_b.encrypt(
    message.encode('utf-8'),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

signature = private_key.sign(
    cipher_text,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

datas = {'public_key': public_key_pem.decode(),
         'signature': signature.hex(),
         'cipher_text': cipher_text.hex()
         }


requests.post('http://flask:5000/receive-datas', json=datas)