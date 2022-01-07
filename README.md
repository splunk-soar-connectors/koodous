[comment]: # "Auto-generated SOAR connector documentation"
# Koodous

Publisher: Splunk  
Connector Version: 2\.0\.2  
Product Vendor: Koodous  
Product Name: Koodous  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app integrates with Koodous to analyze APK files

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Koodous asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_key** |  required  | password | API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[detonate file](#action-detonate-file) - Run the file in the sandbox and retrieve the analysis results  
[get report](#action-get-report) - Query for results of an already completed detonation  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'detonate file'
Run the file in the sandbox and retrieve the analysis results

Type: **investigate**  
Read only: **True**

File detonation may take a while\. If the polling in this action doesn't succeed in getting the file analysis \(which will be indicated through the <b>analysis\_complete</b> key in the summary\), then you should continue polling with the <b>get report</b> action\. If the provided file is not an APK, the action will be uploaded to the Koodous server but fail on the first run\. However, subsequent runs against the same non\-APK file will return results with no information\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault ID of file to detonate | string |  `vault id`  `sha1` 
**attempts** |  optional  | Number of attempts to make while polling | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.attempts | numeric | 
action\_result\.parameter\.vault\_id | string |  `vault id`  `sha1` 
action\_result\.data\.\*\.analysis\.androguard\.activities | string | 
action\_result\.data\.\*\.analysis\.androguard\.androidtv | boolean | 
action\_result\.data\.\*\.analysis\.androguard\.api\_key\.metrica\:api\:level | string | 
action\_result\.data\.\*\.analysis\.androguard\.api\_key\.metrica\:configuration\:api\:level | string | 
action\_result\.data\.\*\.analysis\.androguard\.app\_name | string | 
action\_result\.data\.\*\.analysis\.androguard\.certificate\.issuerDN | string | 
action\_result\.data\.\*\.analysis\.androguard\.certificate\.not\_after | string | 
action\_result\.data\.\*\.analysis\.androguard\.certificate\.not\_before | string | 
action\_result\.data\.\*\.analysis\.androguard\.certificate\.serial | string | 
action\_result\.data\.\*\.analysis\.androguard\.certificate\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.analysis\.androguard\.certificate\.subjectDN | string | 
action\_result\.data\.\*\.analysis\.androguard\.cordova | string | 
action\_result\.data\.\*\.analysis\.androguard\.dexes\.classes\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.analysis\.androguard\.dexes\.classes\.ssdeep | string | 
action\_result\.data\.\*\.analysis\.androguard\.dexes\.classes2\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.analysis\.androguard\.dexes\.classes2\.ssdeep | string | 
action\_result\.data\.\*\.analysis\.androguard\.displayed\_version | string | 
action\_result\.data\.\*\.analysis\.androguard\.filters | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.ads\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.ads\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.ads\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.camera\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.camera\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.camera\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.crypto\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.crypto\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.crypto\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.dynamicbroadcastreceiver\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.dynamicbroadcastreceiver\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.dynamicbroadcastreceiver\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.imei\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.imei\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.imei\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.imsi\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.imsi\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.imsi\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.installedapplications\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.installedapplications\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.installedapplications\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.mcc\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.mcc\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.mcc\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.phonecall\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.phonecall\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.phonecall\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.phonenumber\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.phonenumber\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.phonenumber\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.runbinary\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.runbinary\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.runbinary\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.serialno\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.serialno\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.serialno\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.socket\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.socket\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.socket\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.ssl\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.ssl\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.ssl\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.main\_activity | string | 
action\_result\.data\.\*\.analysis\.androguard\.max\_sdk\_version | string | 
action\_result\.data\.\*\.analysis\.androguard\.min\_sdk\_version | numeric | 
action\_result\.data\.\*\.analysis\.androguard\.new\_permissions | string | 
action\_result\.data\.\*\.analysis\.androguard\.package\_name | string | 
action\_result\.data\.\*\.analysis\.androguard\.permissions | string | 
action\_result\.data\.\*\.analysis\.androguard\.providers | string | 
action\_result\.data\.\*\.analysis\.androguard\.receivers | string | 
action\_result\.data\.\*\.analysis\.androguard\.services | string | 
action\_result\.data\.\*\.analysis\.androguard\.signature\_name | string | 
action\_result\.data\.\*\.analysis\.androguard\.target\_sdk\_version | numeric | 
action\_result\.data\.\*\.analysis\.androguard\.urls | string |  `url` 
action\_result\.data\.\*\.analysis\.androguard\.version\_code | string | 
action\_result\.data\.\*\.analysis\.androguard\.wearable | boolean | 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.category | string | 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.crc32 | string | 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.md5 | string |  `md5` 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.sha512 | string | 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.size | numeric | 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.ssdeep | string | 
action\_result\.data\.\*\.analysis\.droidbox | string | 
action\_result\.data\.\*\.analysis\.droidbox\.dexclass\.\*\.path | string | 
action\_result\.data\.\*\.analysis\.droidbox\.dexclass\.\*\.pid | numeric | 
action\_result\.data\.\*\.analysis\.droidbox\.dexclass\.\*\.processname | string | 
action\_result\.data\.\*\.analysis\.droidbox\.dexclass\.\*\.tid | numeric | 
action\_result\.data\.\*\.analysis\.droidbox\.dexclass\.\*\.time | numeric | 
action\_result\.data\.\*\.analysis\.droidbox\.filesread\.\*\.data | string | 
action\_result\.data\.\*\.analysis\.droidbox\.filesread\.\*\.name | string | 
action\_result\.data\.\*\.analysis\.droidbox\.filesread\.\*\.pid | numeric | 
action\_result\.data\.\*\.analysis\.droidbox\.filesread\.\*\.processname | string | 
action\_result\.data\.\*\.analysis\.droidbox\.filesread\.\*\.tid | numeric | 
action\_result\.data\.\*\.analysis\.droidbox\.filesread\.\*\.time | numeric | 
action\_result\.data\.\*\.analysis\.scanning\_date | string | 
action\_result\.data\.\*\.analysis\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.analysis\.status | string | 
action\_result\.data\.\*\.overview\.analyzed | boolean | 
action\_result\.data\.\*\.overview\.app | string | 
action\_result\.data\.\*\.overview\.company | string | 
action\_result\.data\.\*\.overview\.corrupted | boolean | 
action\_result\.data\.\*\.overview\.created\_on | numeric | 
action\_result\.data\.\*\.overview\.detected | boolean | 
action\_result\.data\.\*\.overview\.displayed\_version | string | 
action\_result\.data\.\*\.overview\.image | string | 
action\_result\.data\.\*\.overview\.is\_apk | boolean | 
action\_result\.data\.\*\.overview\.md5 | string |  `md5` 
action\_result\.data\.\*\.overview\.on\_devices | boolean | 
action\_result\.data\.\*\.overview\.package\_name | string | 
action\_result\.data\.\*\.overview\.rating | numeric | 
action\_result\.data\.\*\.overview\.repo | string | 
action\_result\.data\.\*\.overview\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.overview\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.overview\.size | numeric | 
action\_result\.data\.\*\.overview\.stored | boolean | 
action\_result\.data\.\*\.overview\.tags | string | 
action\_result\.data\.\*\.overview\.trusted | boolean | 
action\_result\.summary\.analysis\_complete | boolean | 
action\_result\.summary\.sha256 | string |  `sha256` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get report'
Query for results of an already completed detonation

Type: **investigate**  
Read only: **True**

Either the <b>sha256</b> or <b>vault\_id</b> should be specified\. If both are specified, the <b>vault\_id</b> parameter will be used\. You do not need to be the one who detonated a file to retrieve a report\. As long as you know the sha256 \(or, have the file in the vault\) of the APK you want to analyze, you could run this action\. The <b>attempts</b> parameter is how many times this action will poll for analysis results\. By default, this number is only 1\. If you are polling after <b>detonate file</b> timed out, then you will want to increase this to a higher number\. There will be a 30 second interval between each polling attempt\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sha256** |  optional  | sha256 hash of file to get analysis of | string |  `sha256` 
**vault\_id** |  optional  | Vault ID, will check if there is an existing report for this file | string |  `vault id`  `sha1` 
**attempts** |  optional  | Number of attempts to make while polling | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.attempts | numeric | 
action\_result\.parameter\.sha256 | string |  `sha256` 
action\_result\.parameter\.vault\_id | string |  `vault id`  `sha1` 
action\_result\.data\.\*\.analysis\.androguard\.activities | string | 
action\_result\.data\.\*\.analysis\.androguard\.androidtv | boolean | 
action\_result\.data\.\*\.analysis\.androguard\.api\_key\.metrica\:api\:level | string | 
action\_result\.data\.\*\.analysis\.androguard\.api\_key\.metrica\:configuration\:api\:level | string | 
action\_result\.data\.\*\.analysis\.androguard\.app\_name | string | 
action\_result\.data\.\*\.analysis\.androguard\.certificate\.issuerDN | string | 
action\_result\.data\.\*\.analysis\.androguard\.certificate\.not\_after | string | 
action\_result\.data\.\*\.analysis\.androguard\.certificate\.not\_before | string | 
action\_result\.data\.\*\.analysis\.androguard\.certificate\.serial | string | 
action\_result\.data\.\*\.analysis\.androguard\.certificate\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.analysis\.androguard\.certificate\.subjectDN | string | 
action\_result\.data\.\*\.analysis\.androguard\.cordova | string | 
action\_result\.data\.\*\.analysis\.androguard\.dexes\.classes\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.analysis\.androguard\.dexes\.classes\.ssdeep | string | 
action\_result\.data\.\*\.analysis\.androguard\.dexes\.classes2\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.analysis\.androguard\.dexes\.classes2\.ssdeep | string | 
action\_result\.data\.\*\.analysis\.androguard\.displayed\_version | string | 
action\_result\.data\.\*\.analysis\.androguard\.filters | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.ads\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.ads\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.ads\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.camera\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.camera\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.camera\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.crypto\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.crypto\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.crypto\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.dynamicbroadcastreceiver\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.dynamicbroadcastreceiver\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.dynamicbroadcastreceiver\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.imei\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.imei\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.imei\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.imsi\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.imsi\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.imsi\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.installedapplications\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.installedapplications\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.installedapplications\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.mcc\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.mcc\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.mcc\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.phonecall\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.phonecall\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.phonecall\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.phonenumber\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.phonenumber\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.phonenumber\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.runbinary\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.runbinary\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.runbinary\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.serialno\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.serialno\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.serialno\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.socket\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.socket\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.socket\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.ssl\.\*\.class | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.ssl\.\*\.code | string | 
action\_result\.data\.\*\.analysis\.androguard\.functionalities\.ssl\.\*\.method | string | 
action\_result\.data\.\*\.analysis\.androguard\.main\_activity | string | 
action\_result\.data\.\*\.analysis\.androguard\.max\_sdk\_version | string | 
action\_result\.data\.\*\.analysis\.androguard\.min\_sdk\_version | numeric | 
action\_result\.data\.\*\.analysis\.androguard\.new\_permissions | string | 
action\_result\.data\.\*\.analysis\.androguard\.package\_name | string | 
action\_result\.data\.\*\.analysis\.androguard\.permissions | string | 
action\_result\.data\.\*\.analysis\.androguard\.providers | string | 
action\_result\.data\.\*\.analysis\.androguard\.receivers | string | 
action\_result\.data\.\*\.analysis\.androguard\.services | string | 
action\_result\.data\.\*\.analysis\.androguard\.signature\_name | string | 
action\_result\.data\.\*\.analysis\.androguard\.target\_sdk\_version | numeric | 
action\_result\.data\.\*\.analysis\.androguard\.urls | string |  `url` 
action\_result\.data\.\*\.analysis\.androguard\.version\_code | string | 
action\_result\.data\.\*\.analysis\.androguard\.wearable | boolean | 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.category | string | 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.crc32 | string | 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.md5 | string |  `md5` 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.sha512 | string | 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.size | numeric | 
action\_result\.data\.\*\.analysis\.cuckoo\.target\.file\.ssdeep | string | 
action\_result\.data\.\*\.analysis\.droidbox | string | 
action\_result\.data\.\*\.analysis\.droidbox\.dexclass\.\*\.path | string | 
action\_result\.data\.\*\.analysis\.droidbox\.dexclass\.\*\.pid | numeric | 
action\_result\.data\.\*\.analysis\.droidbox\.dexclass\.\*\.processname | string | 
action\_result\.data\.\*\.analysis\.droidbox\.dexclass\.\*\.tid | numeric | 
action\_result\.data\.\*\.analysis\.droidbox\.dexclass\.\*\.time | numeric | 
action\_result\.data\.\*\.analysis\.droidbox\.filesread\.\*\.data | string | 
action\_result\.data\.\*\.analysis\.droidbox\.filesread\.\*\.name | string | 
action\_result\.data\.\*\.analysis\.droidbox\.filesread\.\*\.pid | numeric | 
action\_result\.data\.\*\.analysis\.droidbox\.filesread\.\*\.processname | string | 
action\_result\.data\.\*\.analysis\.droidbox\.filesread\.\*\.tid | numeric | 
action\_result\.data\.\*\.analysis\.droidbox\.filesread\.\*\.time | numeric | 
action\_result\.data\.\*\.analysis\.scanning\_date | string | 
action\_result\.data\.\*\.analysis\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.analysis\.status | string | 
action\_result\.data\.\*\.overview\.analyzed | boolean | 
action\_result\.data\.\*\.overview\.app | string | 
action\_result\.data\.\*\.overview\.company | string | 
action\_result\.data\.\*\.overview\.corrupted | boolean | 
action\_result\.data\.\*\.overview\.created\_on | numeric | 
action\_result\.data\.\*\.overview\.detected | boolean | 
action\_result\.data\.\*\.overview\.displayed\_version | string | 
action\_result\.data\.\*\.overview\.image | string | 
action\_result\.data\.\*\.overview\.is\_apk | boolean | 
action\_result\.data\.\*\.overview\.md5 | string |  `md5` 
action\_result\.data\.\*\.overview\.on\_devices | boolean | 
action\_result\.data\.\*\.overview\.package\_name | string | 
action\_result\.data\.\*\.overview\.rating | numeric | 
action\_result\.data\.\*\.overview\.repo | string | 
action\_result\.data\.\*\.overview\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.overview\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.overview\.size | numeric | 
action\_result\.data\.\*\.overview\.stored | boolean | 
action\_result\.data\.\*\.overview\.tags | string | 
action\_result\.data\.\*\.overview\.trusted | boolean | 
action\_result\.summary\.analysis\_complete | boolean | 
action\_result\.summary\.sha256 | string |  `sha256` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 