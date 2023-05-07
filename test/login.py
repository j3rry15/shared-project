from json import dumps

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.ioloop import IOLoop
from tornado.web import Application

from .base import BaseTest

from api.handlers.login import LoginHandler

import urllib.parse

class LoginHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/login', LoginHandler)])
        super().setUpClass()

    @coroutine
    def register(self):
        # updating the registration code to include the hashing as without this the login tests fail as the password is being written directly to the db in this test and not being hashed
        salt = b"\x12\xfb\x1bA\xa2\xe3\x06\xb6n\xf6\x11\x97\x00\x0c`\xf5S\xa8\xba\xf3\xf3'\xb3:h\x9f\xdaZ\xa0l\x89\xcf"
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
        passphrase = self.password
        passphrase_bytes = bytes(passphrase, "utf-8")
        hashed_passphrase = kdf.derive(passphrase_bytes)
        yield self.get_app().db.users.insert_one({
            'email': self.email,
            'password': hashed_passphrase,
            'displayName': 'testDisplayName'
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'

        IOLoop.current().run_sync(self.register)

    def test_login(self):
        body = {
          'email': self.email,
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_case_insensitive(self):
        body = {
          'email': self.email.swapcase(),
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_wrong_email(self):
        body = {
          'email': 'wrongUsername',
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)

    def test_login_wrong_password(self):
        body = {
          'email': self.email,
          'password': 'wrongPassword'
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)
