from tornado.web import authenticated

from .auth import AuthHandler
from cryptography.fernet import Fernet
class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = self.current_user['display_name']

        # Decryption setup
        cipher_suite = Fernet(b'HWDb-3q5SJnTJVQIr5eg2i-M5br9fkaJAZTe10rBhB0=')

        # Decrypt and Show disabilities in array, if previously provided, else don't mention
        if self.current_user['disabilities']:
            unencrypted_disabilities = []
            for disability in self.current_user['disabilities']:
                unencrypted_disabilities.append(cipher_suite.decrypt(disability).decode())
            self.response['disabilities'] = unencrypted_disabilities
        # Decrypt and Show phone number, if previously provided, else don't mention
        if self.current_user['phone_number']:
            self.response['phone_number'] = cipher_suite.decrypt(self.current_user['phone_number']).decode()
        # Decrypt and Show full name, if previously provided, else don't mention
        if self.current_user['full_name']:
            self.response['full_name'] = cipher_suite.decrypt(self.current_user['full_name']).decode()
        # Decrypt and Show date of birth, if previously provided, else don't mention
        if self.current_user['date_of_birth']:
            self.response['date_of_birth'] = cipher_suite.decrypt(self.current_user['date_of_birth']).decode()
        self.write_json()
