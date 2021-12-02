# File: koodous_consts.py
#
# Copyright (c) 2018-2021 Splunk Inc.
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
PHANTOM_ERR_CODE_UNAVAILABLE = "Error code unavailable"
PHANTOM_ERR_MSG_UNAVAILABLE = "Unknown error occurred. Please check the asset configuration and|or action parameters."

VAULT_ERR_INVALID_VAULT_ID = "Invalid Vault ID"
VAULT_ERR_FILE_NOT_FOUND = "Vault file could not be found with supplied Vault ID"

KOODOUS_BASE_URL = 'https://api.koodous.com'
KOODOUS_SUCC_TEST_CONNECTIVITY = "Test connectivity passed"

KOODOUS_ERR_TEST_CONNECTIVITY = "Test Connectivity Failed"
KOODOUS_ERR_INVALID_ATTEMPT_PARAM = "Attempts must be integer number. Error: {0}"
KOODOUS_ERR_GET_REPORT_PARAMS = "Must specify either 'sha256' or 'vault_id'"
KOODOUS_ERR_UPLOADING_URL = "Error retrieving upload URL"
