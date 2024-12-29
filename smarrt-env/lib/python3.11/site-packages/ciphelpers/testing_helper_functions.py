from hamcrest import *


def check_json(json_expected, json_response):
    if type(json_expected) is list:
        for i in range(0, len(json_expected)):
            check_json(json_expected[i], json_response[i])
            check_json(json_response[i], json_expected[i])
    else:
        for key, value in json_expected.items():
            if type(value) is dict:
                assert_that(json_response, has_key(key))
                check_json(value, json_response[key])
                check_json(json_response[key], value)
            elif type(value) is list:
                for i in range(0, len(value)):
                    check_json(json_expected[key][i], json_response[key][i])
                    check_json(json_response[key][i], json_expected[key][i])
            else:
                assert_that(json_response, has_entry(key, value))
