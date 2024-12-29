class CipException(Exception):
    def __init__(self, error_code, http_status_code, message):
        Exception.__init__(self)
        self.error_code = error_code
        self.message = message
        self.http_status_code = http_status_code

    def get_message_json(self):
        return {
            "error_code": self.error_code,
            "message": self.message,
            "response": ""
        }


def check_exceptions(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except CipException as ex:
            return ex.get_message_json(), ex.http_status_code
        except Exception as ex:
            return {'message': str(ex)}, 500

    return wrapper