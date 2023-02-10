import json
import requests
import base64
from flask import Flask
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

pk_response = requests.get("http://127.0.0.1:5000/sendPublicKey").text.encode()
public_key_b = serialization.load_pem_public_key(pk_response)

message = b"Alo Mundo!"

cipher_text = public_key_b.encrypt(
    message,
    OAEP(
        mgf=MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

signature = private_key.sign(
    cipher_text,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

public_key_pem_by = base64.b64encode(public_key_pem)
signature_by = base64.b64encode(signature)
cipher_text_by = base64.b64encode(cipher_text)

datas = {'public_key_pem': public_key_pem_by.decode(),
         'signature': signature_by.decode(),
         'cipher_text': cipher_text_by.decode()
         }


@app.route('/sendDatas', methods=['GET'])
async def sendToAppB():
    return json.dumps(datas)


app.run(port=5001)
