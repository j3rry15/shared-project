from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from .base import BaseHandler

class RegistrationHandler(BaseHandler):

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
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        # hash the password here before sending to DB
        salt = b"\x12\xfb\x1bA\xa2\xe3\x06\xb6n\xf6\x11\x97\x00\x0c`\xf5S\xa8\xba\xf3\xf3'\xb3:h\x9f\xdaZ\xa0l\x89\xcf"
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
        passphrase = password
        passphrase_bytes = bytes(passphrase, "utf-8")
        hashed_passphrase = kdf.derive(passphrase_bytes)

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_passphrase,
            'displayName': display_name
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()
