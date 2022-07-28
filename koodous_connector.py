# File: koodous_connector.py
#
# Copyright (c) 2018-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
import json
# Usage of the consts file is recommended
import time

import phantom.app as phantom
import phantom.rules as phrules
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from koodous_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class KoodousConnector(BaseConnector):

    def __init__(self):
        super(KoodousConnector, self).__init__()
        self._state = None
        self._api_key = None
        self._base_url = None
        self._headers = None

    def initialize(self):
        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}

        config = self.get_config()
        self._base_url = KOODOUS_BASE_URL
        self._api_key = config['api_key']
        self._headers = {
            'Authorization': 'Token {}'.format(self._api_key)
        }
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_msg = KOODOUS_ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception:
            self.debug_print("Error occurred while fetching exception information")

        if not error_code:
            error_text = "Error Message: {}".format(error_msg)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

        return error_text

    def _process_empty_response(self, response, action_result):

        if response.status_code in [200, 204, 201]:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        if response.status_code:
            return RetVal(phantom.APP_SUCCESS, {})

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
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
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(err_msg)), None)

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

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

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
            url = '{0}{1}'.format(self._base_url, endpoint)
        else:
            url = endpoint

        try:
            r = request_func(
                url,
                json=data,
                headers=headers,
                files=files,
                verify=config.get('verify_server_cert', False),
                params=params,
                timeout=KOODOUS_DEFAULT_TIMEOUT
            )
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(err_msg)), resp_json)

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

        try:
            success, message, vault_info = phrules.vault_info(vault_id=vault_id)
            vault_info = list(vault_info)[0]
        except IndexError:
            return action_result.set_status(phantom.APP_ERROR, KOODOUS_VAULT_ERR_FILE_NOT_FOUND), None, None
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, KOODOUS_VAULT_ERR_INVALID_VAULT_ID), None, None

        file_sha256 = vault_info.get('metadata').get('sha256')

        return phantom.APP_SUCCESS, file_sha256, vault_info

    def _upload_file(self, action_result, file_info):
        endpoint = '/apks/{sha256}/get_upload_url'.format(sha256=file_info['metadata']['sha256'])
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, KOODOUS_ERR_UPLOADING_URL)

        upload_url = response.get('upload_url')

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

    def _get_report(self, action_result, sha256, attempts=1, analysis_type="all", last_yara_analysis_at=None):

        data = {}

        endpoint = KOODOUD_FILE_INFO_ENDPOINT.format(sha256=sha256)
        analysis_complete = False
        analysis_response = None
        for i in range(0, attempts):
            self.save_progress("Polling for report, on attempt {} of {}".format(
                i + 1,
                attempts)
            )

            ret_val, response = self._make_rest_call(endpoint, action_result)
            if phantom.is_fail(ret_val):
                return ret_val

            if analysis_type == 'yara' and response.get(KOODOUS_ANALYSIS_TYPES[analysis_type]) != last_yara_analysis_at:
                analysis_complete = True
                break

            if (analysis_type in ['static', 'dynamic'] and response.get(KOODOUS_ANALYSIS_TYPES[analysis_type])) or (
                    analysis_type == KOODOUS_DEFAULT_ANALYSIS_TYPE and (response.get(KOODOUS_ANALYSIS_TYPES['static']) or response.get(
                    KOODOUS_ANALYSIS_TYPES['dynamic']))):
                analysis_complete = True
                endpoint = '/apks/{sha256}/analysis'.format(sha256=sha256)
                ret_val, analysis_response = self._make_rest_call(endpoint, action_result)
                if phantom.is_fail(ret_val):
                    return ret_val
                break

            if i != attempts - 1:
                # Don't sleep if there are no more attempts left
                time.sleep(30)

        action_result.update_summary({
            'sha256': sha256,
            'analysis_complete': analysis_complete
        })
        data['overview'] = response
        if analysis_response:
            data['analysis'] = analysis_response
        action_result.add_data(data)

        if analysis_complete:
            msg = "Successfully retrieved overview and analysis"
        else:
            msg = "Successfully retrieved overview, though no file could be found. " \
                    "Either the {} hasn't been started or is still running".format(
                        "analysis" if analysis_type == "all" else "{} analysis".format(analysis_type))

        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Making call to validate API key...")

        params = {
            'search': 'Whatsapp'
        }

        ret_val, _ = self._make_rest_call('/apks', action_result, params=params)
        if phantom.is_fail(ret_val):
            self.save_progress(KOODOUS_ERR_TEST_CONNECTIVITY)
            return ret_val

        self.save_progress(KOODOUS_SUCC_TEST_CONNECTIVITY)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            attempts = int(param.get('attempts', 1))
            if attempts < 1:
                attempts = 1
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, KOODOUS_ERR_INVALID_ATTEMPT_PARAM.format(err_msg)), None)

        vault_id = param['vault_id']
        analysis_type = param.get('analysis_type', KOODOUS_DEFAULT_ANALYSIS_TYPE)

        if analysis_type not in KOODOUS_ANALYSIS_TYPE_LIST:
            return action_result.set_status(phantom.APP_ERROR,
            "Please provide a valid input from {} in the 'analysis_type' action parameter".format(KOODOUS_ANALYSIS_TYPE_LIST))

        force_yara_analysis = param.get('force_yara_analysis', False)

        ret_val, sha256, file_info = self._get_vault_file_sha256(action_result, vault_id)
        if phantom.is_fail(ret_val):
            return ret_val

        if not file_info['name'].endswith(".apk"):
            return action_result.set_status(phantom.APP_ERROR, KOODOUS_ERR_FILE_NOT_APK)

        if not sha256:
            return action_result.set_status(phantom.APP_ERROR, KOODOUS_ERR_GET_REPORT_PARAMS)

        last_yara_analysis_at = None
        # First check if this file has already been added
        endpoint = KOODOUD_FILE_INFO_ENDPOINT.format(sha256=sha256)
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            ret_val = self._upload_file(action_result, file_info)
            if phantom.is_fail(ret_val):
                return ret_val
            endpoint = KOODOUD_FILE_INFO_ENDPOINT.format(sha256=sha256)
            ret_val, response = self._make_rest_call(endpoint, action_result)
            if phantom.is_fail(ret_val):
                return ret_val

        # Check if we need to run analysis
        if analysis_type in ['dynamic', KOODOUS_DEFAULT_ANALYSIS_TYPE] and not response.get(KOODOUS_ANALYSIS_TYPES['dynamic']):
            endpoint = KOODOUS_ANALYSIS_ENDPOINT.format(sha256=sha256, analysis_type='analyze_dynamic')
            ret_val, _ = self._make_rest_call(endpoint, action_result, method='post')
            if phantom.is_fail(ret_val):
                return ret_val

        if analysis_type in ['static', KOODOUS_DEFAULT_ANALYSIS_TYPE] and not response.get(KOODOUS_ANALYSIS_TYPES['static']):
            endpoint = KOODOUS_ANALYSIS_ENDPOINT.format(sha256=sha256, analysis_type='analyze_static')
            ret_val, _ = self._make_rest_call(endpoint, action_result, method='post')
            if phantom.is_fail(ret_val):
                return ret_val

        if analysis_type in ['yara', KOODOUS_DEFAULT_ANALYSIS_TYPE] and (force_yara_analysis or not response.get(
                    KOODOUS_ANALYSIS_TYPES['yara'])):
            last_yara_analysis_at = response.get(KOODOUS_ANALYSIS_TYPES['yara'])
            endpoint = KOODOUS_ANALYSIS_ENDPOINT.format(sha256=sha256, analysis_type='analyze_yara')
            ret_val, _ = self._make_rest_call(endpoint, action_result, method='post')
            if phantom.is_fail(ret_val):
                return ret_val
        return self._get_report(action_result, sha256, attempts=attempts, analysis_type=analysis_type,
            last_yara_analysis_at=last_yara_analysis_at)

    def _handle_get_report(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            attempts = int(param.get('attempts', 1))
            if attempts < 1:
                attempts = 1
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, KOODOUS_ERR_INVALID_ATTEMPT_PARAM.format(err_msg)), None)

        sha256 = param.get('sha256')
        vault_id = param.get('vault_id')
        if vault_id:
            ret_val, sha256, file_info = self._get_vault_file_sha256(action_result, vault_id)
            if phantom.is_fail(ret_val):
                return ret_val
            if not file_info['name'].endswith(".apk"):
                return action_result.set_status(phantom.APP_ERROR, KOODOUS_ERR_FILE_NOT_APK)

        if not sha256:
            return action_result.set_status(phantom.APP_ERROR, KOODOUS_ERR_GET_REPORT_PARAMS)

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

    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None
    verify = args.verify

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            login_url = '{}login'.format(BaseConnector._get_phantom_base_url())
            r = requests.get(login_url, verify=verify, timeout=KOODOUS_DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=KOODOUS_DEFAULT_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: {}".format(e))
            sys.exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = KoodousConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
