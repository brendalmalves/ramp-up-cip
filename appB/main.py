import base64
import requests
from cryptography.exceptions import InvalidSignature
from flask import Flask
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
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

app = Flask(__name__)

@app.route('/sendPublicKey', methods=['GET'])
async def sendPublicKey():
    return public_key_pem


#receber mensagem, signature e chave publica de appA
pk_response = requests.get("http://127.0.0.1:5001/sendDatas").json()

p_key_A = pk_response['public_key_pem']
signature = pk_response['signature']
msg = pk_response['cipher_text']

public_key_pem_by = base64.b64decode(p_key_A)
public_key_A = serialization.load_pem_public_key(public_key_pem_by)

encrypted_msg = base64.b64decode(msg)
signature_A = base64.b64decode(signature)

try:
    mensagem_verificada = public_key_A.verify(
        signature_A,
        encrypted_msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print('assinatura válida')

except InvalidSignature:
    print('assinatura não é válida')

# decifrar a mensagem recebida
try:
    plaintext = private_key.decrypt(
        encrypted_msg,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

    )
    print(plaintext)
except:
    print('não consegui decifrar')


app.run(port=5000)
