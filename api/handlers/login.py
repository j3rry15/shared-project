from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from .base import BaseHandler

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {
          'password': 1
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        # hash the provided password with same salt as when hashing during registration
        salt = b"\x12\xfb\x1bA\xa2\xe3\x06\xb6n\xf6\x11\x97\x00\x0c`\xf5S\xa8\xba\xf3\xf3'\xb3:h\x9f\xdaZ\xa0l\x89\xcf"
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
        passphrase = password
        passphrase_bytes = bytes(passphrase, "utf-8")
        hashed_passphrase = kdf.derive(passphrase_bytes)

        if user['password'] != hashed_passphrase:
            self.send_error(403, message='The email address and password are invalid!')
            return

        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
