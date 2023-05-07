from cryptography.fernet import Fernet
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.web import authenticated
from .auth import AuthHandler

class AddInfoHandler(AuthHandler):
    @authenticated
    @coroutine
    def post(self):
        try:
            # retrieve the json that was sent in the API Call
            body = json_decode(self.request.body)
        except Exception as e:
            self.send_error(400, message='You must provide details ')
            return

        email = self.current_user['email']

        # setup for encrypting with Fernet
        key = b'HWDb-3q5SJnTJVQIr5eg2i-M5br9fkaJAZTe10rBhB0='
        cipher_suite = Fernet(key)

        # if disabilities are provided, encrypt individually in an array and send to DB
        if "disabilities" in body:
            secure_disabilities = []
            for disability in body['disabilities']:
                secure_disabilities.append(cipher_suite.encrypt(disability.encode()))
            yield self.db.users.update_one({
                'email': email
            }, {
                '$set': {"disabilities": secure_disabilities}
            })
        # if phone number is  provided, encrypt and send to DB
        if "phone_number" in body:
            yield self.db.users.update_one({
                'email': email
            }, {
                '$set': {"phone_number": cipher_suite.encrypt(str(body['phone_number']).encode())}
            })

        # if full name is  provided, encrypt and send to DB
        if "full_name" in body:
            yield self.db.users.update_one({
                'email': email
            }, {
                '$set': {"full_name": cipher_suite.encrypt(body['full_name'].encode())}
            })

        # if DOB is  provided, encrypt and send to DB
        if "date_of_birth" in body:
            yield self.db.users.update_one({
                'email': email
            }, {
                '$set': {"date_of_birth": cipher_suite.encrypt(body['date_of_birth'].encode())}
            })