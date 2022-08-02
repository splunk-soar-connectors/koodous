# File: koodous_consts.py
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

# constants relating to '_get_error_message_from_exception'
KOODOUS_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"

# constants relating to vault file
KOODOUS_VAULT_ERR_INVALID_VAULT_ID = "Invalid Vault ID"
KOODOUS_VAULT_ERR_FILE_NOT_FOUND = "Vault file could not be found with supplied Vault ID"

# constants relating to endpoints
KOODOUS_BASE_URL = 'https://developer.koodous.com'
KOODOUS_APKS_ENDPOINT = '/apks'
KOODOUS_ANALYSIS_ENDPOINT = '/apks/{sha256}/{analysis_type}/'
KOODOUD_FILE_INFO_ENDPOINT = '/apks/{sha256}'
KOODOUS_ANALYSIS_RESULT_ENDPOINT = '/apks/{sha256}/analysis'
KOODOUS_GET_UPLOAD_URL_ENDPOINT = '/apks/{sha256}/get_upload_url'

# constants relating to error and success messages
KOODOUS_SUCC_TEST_CONNECTIVITY = "Test connectivity passed"

KOODOUS_ERR_TEST_CONNECTIVITY = "Test Connectivity Failed"
KOODOUS_ERR_INVALID_ATTEMPT_PARAM = "Please provide a valid Integer value in the 'attempts' action parameter. Error: {0}"
KOODOUS_ERR_GET_REPORT_PARAMS = "Please specify either 'sha256' or 'vault_id'"
KOODOUS_ERR_UPLOADING_URL = "Error retrieving upload URL"

KOODOUS_ERR_FILE_NOT_APK = "Please provide a valid apk file"

KOODOUS_DEFAULT_ANALYSIS_TYPE = "all"
KOODOUS_ANALYSIS_TYPE_LIST = ["all", "static", "dynamic", "yara"]
KOODOUS_ANALYSIS_TYPES = {
    "static": "is_static_analyzed",
    "dynamic": "is_dynamic_analyzed",
    "yara": "last_yara_analysis_at"
}
KOODOUS_DEFAULT_TIMEOUT = 30
