from flask import Flask
from flask import request
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


@app.route('/send-public-key', methods=['GET'])
def send_public_key():
    return public_key_pem


@app.route('/receive-datas', methods=['POST'])
def receive_datas():
    data = request.json
    public_key_a = load_pem_public_key(str.encode(data['public_key']))
    signature = bytes.fromhex(data['signature'])
    cipher_text = bytes.fromhex(data['cipher_text'])

    try:
        public_key_a.verify(
            signature,
            cipher_text,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print('assinatura válida')

    except InvalidSignature:
        print('assinatura não é válida')

    try:
        plaintext = private_key.decrypt(
            cipher_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )).decode('utf-8')
        print(plaintext)
        return '', 200
    except:
        print('não consegui decifrar')
        return '', 400
