import datetime
import pyotp

class TotpAuth:
    def __init__(self, secret=None):
        if secret is None:
            secret = pyotp.random_base32()
        self.secret = secret
        self.totp = pyotp.TOTP(secret)

    def valid(self, token):
        try:
            token = int(token)
            now = datetime.datetime.utcnow()
            time30secsago = now + datetime.timedelta(seconds=-30)
            
            valid_now = self.totp.verify(token)
            valid_past = self.totp.verify(token, for_time=time30secsago)
            
            return valid_now or valid_past
        except Exception as e:
            print("Error: "+str(e))
            return False