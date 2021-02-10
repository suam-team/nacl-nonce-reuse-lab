from flask import Flask, request, render_template
from nacl.secret import SecretBox
import os

FLAG = os.environ.get("FLAG") or "PLEASE_SET_A_FLAG"
KEY = os.environ.get("KEY") or os.urandom(32)
SALT = os.environ.get("SALT") or os.urandom(23)

app = Flask(__name__)

class Encryptor(object):
    def __init__(self, key, salt):
        self.salt = salt
        self.key = key

        try:
            self.salt = self.salt.encode()
        except Exception:
            pass

        try:
            self.key = self.key.encode()
        except Exception:
            pass
    
    def encrypt(self, plaintext):
        nonce = self.salt + os.urandom(24 - len(self.salt))
        box = SecretBox(self.key)
        return box.encrypt(plaintext.encode(), nonce).hex()
    
    def decrypt(self, ciphertext):
        box = SecretBox(self.key)
        return box.decrypt(bytes.fromhex(ciphertext))

encryptor = Encryptor(KEY, SALT)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    plaintext = request.form.get('plaintext')

    if not plaintext or len(plaintext) == 0:
        return "Something wents wrong"

    return encryptor.encrypt(plaintext + FLAG)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    ciphertext = request.form.get('ciphertext')

    plaintext = encryptor.decrypt(ciphertext)
    if not plaintext.decode().endswith(FLAG):
        return "Something wents wrong"
    else:
        return plaintext[:-len(FLAG)]

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
