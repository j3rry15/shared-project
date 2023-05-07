from datetime import datetime
from time import mktime
from tornado.gen import coroutine

from .base import BaseHandler

class AuthHandler(BaseHandler):

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception()
        except:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return
        # retrieve all information from DB
        user = yield self.db.users.find_one({
            'token': token
        }, {
            'email': 1,
            'displayName': 1,
            'expiresIn': 1,
            'disabilities': 1,
            'phone_number': 1,
            'full_name': 1,
            'date_of_birth': 1
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = mktime(datetime.now().utctimetuple())
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return

        #add PII, if they exist, to be available in the result of /user call
        disabilities = []
        if "disabilities" in user:
            disabilities = user['disabilities']
        phone_number = ''
        if 'phone_number' in user:
            phone_number = user['phone_number']
        full_name = ''
        if 'full_name' in user:
            full_name = user['full_name']
        date_of_birth = ''
        if 'date_of_birth' in user:
            date_of_birth = user['date_of_birth']

        self.current_user = {
            'email': user['email'],
            'display_name': user['displayName'],
            'disabilities': disabilities,
            'phone_number': phone_number,
            'full_name': full_name,
            'date_of_birth': date_of_birth
        }
