# File: koodous_consts.py
#
# Copyright (c) 2018-2022 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

PHANTOM_ERR_CODE_UNAVAILABLE = "Error code unavailable"
PHANTOM_ERR_MSG_UNAVAILABLE = "Unknown error occurred. Please check the asset configuration and|or action parameters."

VAULT_ERR_INVALID_VAULT_ID = "Invalid Vault ID"
VAULT_ERR_FILE_NOT_FOUND = "Vault file could not be found with supplied Vault ID"

KOODOUS_BASE_URL = 'https://api.koodous.com'
KOODOUS_SUCC_TEST_CONNECTIVITY = "Test connectivity passed"

KOODOUS_ERR_TEST_CONNECTIVITY = "Test Connectivity Failed"
KOODOUS_ERR_INVALID_ATTEMPT_PARAM = "Please provide a valid Integer value in the 'attempts' action parameter. Error: {0}"
KOODOUS_ERR_GET_REPORT_PARAMS = "Please specify either 'sha256' or 'vault_id'"
KOODOUS_ERR_UPLOADING_URL = "Error retrieving upload URL"
KOODOUS_ERR_GET_REPORT_NOT_APK = "The provided SHA256/Vault_id does not represent an apk file. Please provide a SHA256/Vault_id which represents a valid apk file"
KOODOUS_ERR_FILE_NOT_APK = "Please provide a valid apk file"
