from jsonschema import validate, ValidationError
from .error_handling_helper_functions import CipException
import flask 
import json

class ValidateInput(object):
    def __init__(self, json_schema):
        self.json_schema = json_schema

    def __call__(self, original_func):

        def wrappee(*args, **kwargs):
            try:
                if not hasattr(flask.request, 'json'):
                    raise ValidationError('No json provided.')

                validate(flask.request.json, json.loads(self.json_schema))
            except ValidationError as ex:
                raise CipException(100, 400, str(ex))

            return original_func(*args, **kwargs)

        return wrappee