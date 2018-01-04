# File: koodous_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2018
#
# This unpublished material is proprietary to Phantom Cyber 2017-2018.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Usage of the consts file is recommended
import time
import json
import requests
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class KoodousConnector(BaseConnector):

    def __init__(self):
        super(KoodousConnector, self).__init__()
        self._state = None
        self._api_key = None
        self._base_url = None

    def initialize(self):
        self._state = self.load_state()
        config = self.get_config()
        self._base_url = 'https://api.koodous.com'
        self._api_key = config['api_key']
        self._headers = {
            'Authorization': 'Token {}'.format(self._api_key)
        }
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _process_empty_reponse(self, response, action_result):

        if response.status_code:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        if response.status_code:
            return RetVal(phantom.APP_SUCCESS, {})

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, files=None, method="get", ignore_base_url=False):

        config = self.get_config()

        resp_json = None
        if headers is None:
            headers = {}

        headers.update(self._headers)

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        if not ignore_base_url:
            url = self._base_url + endpoint
        else:
            url = endpoint

        try:
            r = request_func(
                url,
                json=data,
                headers=headers,
                files=files,
                verify=config.get('verify_server_cert', False),
                params=params
            )
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        # Catch a few errors here
        if r.status_code == 405:
            # No analysis could be found for given sha256
            return RetVal(phantom.APP_SUCCESS, {})

        if r.status_code == 409:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "This file has already been uploaded"))

        if r.status_code == 415:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "This is not an APK file"))

        return self._process_response(r, action_result)

    def _get_vault_file_sha256(self, action_result, vault_id):
        file_info = Vault.get_file_info(vault_id=vault_id)
        if len(file_info) == 0:
            return action_result.set_status(phantom.APP_ERROR, "No files in vault match given ID")

        return phantom.APP_SUCCESS, file_info[0]['metadata']['sha256']

    def _upload_file(self, action_result, file_info):
        endpoint = '/apks/{sha256}/get_upload_url'.format(sha256=file_info['metadata']['sha256'])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Error retrieving upload URL")

        upload_url = response['upload_url']

        ret_val, response = self._make_rest_call(
            upload_url,
            action_result,
            method='post',
            files={'file': open(file_info['path'], 'rb')},
            ignore_base_url=True
        )

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Error uploading file: {}".format(action_result.get_message()))

        return phantom.APP_SUCCESS

    def _get_report(self, action_result, sha256, attempts=1):
        data = {}

        endpoint = '/apks/{sha256}'.format(sha256=sha256)
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        data['overview'] = response
        analysis_complete = False

        endpoint = '/apks/{sha256}/analysis'.format(sha256=sha256)
        for i in range(0, attempts):
            self.save_progress("Polling for report, on attempt {} of {}".format(
                i + 1,
                attempts)
            )

            ret_val, response = self._make_rest_call(endpoint, action_result)
            if phantom.is_fail(ret_val):
                return ret_val

            if response:
                analysis_complete = True
                break

            if i != attempts - 1:
                # Don't sleep if there are no more attempts left
                time.sleep(30)

        data['analysis'] = response
        action_result.add_data(data)
        action_result.update_summary({
            'sha256': sha256,
            'analysis_complete': analysis_complete
        })

        if response:
            msg = "Successfully retrieved overview and analysis"
        else:
            msg = "Successfully retrieved overview, though no file could be found." \
                  "Either it hasn't been started or is still running"

        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Making call to validate API key...")

        params = {
            'search': 'Whatsapp'
        }

        ret_val, response = self._make_rest_call('/apks', action_result, params=params)
        if phantom.is_fail(ret_val):
            self.save_progress("Test connectivity failed")
            return ret_val

        self.save_progress("Test connectivity passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_file(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        attempts = int(param.get('attempts', 10))
        if attempts < 1:
            attempts = 1

        vault_id = param['vault_id']

        try:
            file_info = Vault.get_file_info(vault_id=vault_id)[0]
        except:
            return action_result.set_status(phantom.APP_ERROR, "Invalid Vault ID")

        # First check if this file has already been added
        endpoint = '/apks/{sha256}'.format(sha256=file_info['metadata']['sha256'])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            analyzed = False
            ret_val = self._upload_file(action_result, file_info)
            if phantom.is_fail(ret_val):
                return ret_val
        else:
            analyzed = response['analyzed']

        # Check if we need to run analysis
        if not analyzed:
            endpoint = '/apks/{sha256}/analyze'.format(sha256=file_info['metadata']['sha256'])
            ret_val, response = self._make_rest_call(endpoint, action_result)
            if phantom.is_fail(ret_val):
                return ret_val

        return self._get_report(action_result, file_info['metadata']['sha256'], attempts=attempts)

    def _handle_get_report(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        attempts = int(param.get('attempts', 1))
        if attempts < 1:
            attempts = 1

        sha256 = param.get('sha256')
        vault_id = param.get('vault_id')
        if vault_id:
            ret_val, sha256 = self._get_vault_file_sha256(action_result, vault_id)
            if phantom.is_fail(ret_val):
                return ret_val

        if not sha256:
            return action_result.set_status(
                phantom.APP_ERROR, "Must specify either 'sha256' or 'vault_id'"
            )

        return self._get_report(action_result, sha256, attempts=attempts)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'detonate_file':
            ret_val = self._handle_detonate_file(param)

        elif action_id == 'get_report':
            ret_val = self._handle_get_report(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = KoodousConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
