import app
from threading import Thread

def build_response(error_code, message, response, status_code):

    return {
        "error_code": error_code,
        "message": message,
        "response": response
    }, status_code


def build_working_response(service, status, error_description='', error_code=''):
    return {
        "service": service,
        "status": status,
        "error_description": error_description,
        "error_code": error_code
    }

def log_request(f):
    def wrapper(*args, **kwargs):
        message = "Method: " + str(request.method) + " endpoint: " + request.full_path + " body: "
        if request.data:
            message += str(request.data)

        app.log.info(200, message='Request recebido: ' + message)
        response = f(*args, **kwargs)
        return response
    return wrapper


def process_async(async_function):
    def decorator(f):
        def wrapper(*args, **kwargs):
            thread = Thread(target=async_function, args=args, kwargs=kwargs)
            thread.start()
            return f(*args, **kwargs)
        return wrapper
    return decorator


def last_commit():
    """Return last commit and your date"""
    return subprocess.check_output(['git', 'log', '-1', '--pretty=format:"%h"'],
                                   universal_newlines=False).decode("utf-8").replace('\"', '')


def last_commit_datetime():
    """Return last commit and your date"""
    return subprocess.check_output(['git', 'log', '-1', '--pretty=format:"%cd"'],
                                   universal_newlines=False).decode("utf-8").replace('\"', '')


def last_tag():
    """Return last tag"""
    return subprocess.check_output(['git', 'describe', '--abbrev=0', '--tags'],
                                   universal_newlines=False).decode("utf-8").replace('\n', '')


