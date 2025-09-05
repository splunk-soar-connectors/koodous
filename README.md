# Koodous

Publisher: Splunk <br>
Connector Version: 2.1.2 <br>
Product Vendor: Koodous <br>
Product Name: Koodous <br>
Minimum Product Version: 5.2.0

This app integrates with Koodous to analyze APK files

## Playbook Backward Compatibility

- The parameters have been added in the below-existing action. Hence, it is requested to update
  existing playbooks created in the earlier versions of the app by re-inserting | modifying |
  deleting the corresponding action blocks.

  - Detonate File - Below parameter have been added.

    - 'analysis type'
    - 'force yara analysis'

## Note:

If negative or zero value is passed in the 'attempts' parameter in 'detonate_file' and 'get_report'
action, it will be considered as 1.

### Configuration variables

This table lists the configuration variables required to operate Koodous. These variables are specified when configuring a Koodous asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** | required | password | API Key |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration <br>
[detonate file](#action-detonate-file) - Run the file in the sandbox and retrieve the analysis results <br>
[get report](#action-get-report) - Query for results of an already completed detonation

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'detonate file'

Run the file in the sandbox and retrieve the analysis results

Type: **generic** <br>
Read only: **False**

File detonation may take a while. If the polling in this action doesn't succeed in getting the file analysis (which will be indicated through the <b>analysis_complete</b> key in the summary), then you should continue polling with the <b>get report</b> action. If the <b>analysis_type</b> is 'yara' and <b>force_yara_analysis</b> is false, then the 'yara' analysis will only be performed if it has not been performed before. To perform yara analysis repeatedly, keep <b>force_yara_analysis</b> as true.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | Vault ID of file to detonate | string | `vault id` `sha1` |
**analysis_type** | optional | Type of analysis | string | |
**attempts** | optional | Number of attempts to make while polling | numeric | |
**force_yara_analysis** | optional | Perform Yara analysis | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.analysis_type | string | | all |
action_result.parameter.attempts | numeric | | 10 |
action_result.parameter.force_yara_analysis | boolean | | False True |
action_result.parameter.vault_id | string | `vault id` `sha1` | x5ac7cfc8f90a146f85716c27d7527b6af17287x |
action_result.data.\*.analysis.androguard.activities | string | | com.test.msdk.shell.MVActivity |
action_result.data.\*.analysis.androguard.androidtv | boolean | | True False |
action_result.data.\*.analysis.androguard.api_key.com::startapp::sdk::APPLICATION_ID | string | | |
action_result.data.\*.analysis.androguard.api_key.com::startapp::sdk::RETURN_ADS_ENABLED | string | | true |
action_result.data.\*.analysis.androguard.api_key.metrica:api:level | string | | 62 |
action_result.data.\*.analysis.androguard.api_key.metrica:configuration:api:level | string | | 1 |
action_result.data.\*.analysis.androguard.api_key.required_amazon_package:com::amazon::application::compatibility::enforcer::sdk::library | string | | 19000 |
action_result.data.\*.analysis.androguard.api_key.required_amazon_package:com::amazon::device::messaging::sdk::library | string | | 2074700 |
action_result.data.\*.analysis.androguard.app_name | string | | Test app |
action_result.data.\*.analysis.androguard.certificate.issuerDN | string | | /C=NO/ST=Oslo/L=Oslo/O=Opera Software ASA/OU=Opera Mini/CN=Opera Android CA |
action_result.data.\*.analysis.androguard.certificate.not_after | string | | May 25 08:27:16 2114 GMT |
action_result.data.\*.analysis.androguard.certificate.not_before | string | | Jun 18 08:27:16 2014 GMT |
action_result.data.\*.analysis.androguard.certificate.serial | string | `sha1` | testtestE07403744EF8827071A939D3testtest |
action_result.data.\*.analysis.androguard.certificate.sha1 | string | `sha1` | testtestE07403744EF8827071A939D3testtest |
action_result.data.\*.analysis.androguard.certificate.subjectDN | string | | /C=NO/ST=Oslo/L=Oslo/O=Opera Software ASA/OU=Opera Mini/CN=Opera Android CA |
action_result.data.\*.analysis.androguard.cordova | string | | |
action_result.data.\*.analysis.androguard.dexes.classes.sha256 | string | `sha256` | testtest45822f127329747ebc545fec8ca33301a1416a8e0e714e0ctesttest |
action_result.data.\*.analysis.androguard.dexes.classes.ssdeep | string | | 98304:ncDdVScJfr4RBrv2yP+KdFi+mNUsQBbaju6hEeRxQ:ncp0wfr4RBrv2yP+KdY+iUsDtesttest |
action_result.data.\*.analysis.androguard.dexes.classes2.sha256 | string | `sha256` | 7f857344077ffc64899cf60bdf1dbef9776250d55f803e9a23831da7testtest |
action_result.data.\*.analysis.androguard.dexes.classes2.ssdeep | string | | 24576:Zmh4ZRdgplwdv4X5l5mE1RQ32WpQMzMAlgHz87OUsDvp8+UTVNFkxApmkwOvS:bRQlG4X8P2WpQ0MAlgTtesttest |
action_result.data.\*.analysis.androguard.displayed_version | string | | 32.0.2254.123747 |
action_result.data.\*.analysis.androguard.filters | string | | android.intent.action.PACKAGE_REMOVED |
action_result.data.\*.analysis.androguard.functionalities.SMS.\*.class | string | | Lcom/admarvel/android/ads/Utils; |
action_result.data.\*.analysis.androguard.functionalities.SMS.\*.code | string | | const-string v5, 'sms_body' |
action_result.data.\*.analysis.androguard.functionalities.SMS.\*.method | string | | a |
action_result.data.\*.analysis.androguard.functionalities.ads.\*.class | string | | Laje$3; |
action_result.data.\*.analysis.androguard.functionalities.ads.\*.code | string | | const-string v5, 'AdMob error code: ' |
action_result.data.\*.analysis.androguard.functionalities.ads.\*.method | string | | onAdFailedToLoad |
action_result.data.\*.analysis.androguard.functionalities.camera.\*.class | string | | Lcom/opera/android/custom_views/GenericCameraView; |
action_result.data.\*.analysis.androguard.functionalities.camera.\*.code | string | | invoke-virtual v0, v1, Landroid/hardware/Camera;->setPreviewDisplay(Landroid/view/SurfaceHolder;)V |
action_result.data.\*.analysis.androguard.functionalities.camera.\*.method | string | | b |
action_result.data.\*.analysis.androguard.functionalities.crypto.\*.class | string | | Labe; |
action_result.data.\*.analysis.androguard.functionalities.crypto.\*.code | string | | invoke-virtual v0, v1, Ljava/security/MessageDigest;->digest(\[B)\[B |
action_result.data.\*.analysis.androguard.functionalities.crypto.\*.method | string | | e |
action_result.data.\*.analysis.androguard.functionalities.dynamicbroadcastreceiver.\*.class | string | | Labv; |
action_result.data.\*.analysis.androguard.functionalities.dynamicbroadcastreceiver.\*.code | string | | invoke-virtual v1, v2, v3, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver; Landroid/content/IntentFilter;)Landroid/content/Intent; |
action_result.data.\*.analysis.androguard.functionalities.dynamicbroadcastreceiver.\*.method | string | | g |
action_result.data.\*.analysis.androguard.functionalities.iccid.\*.class | string | | Lcom/apprupt/sdk/CvAppInfo; |
action_result.data.\*.analysis.androguard.functionalities.iccid.\*.code | string | | invoke-virtual v0, Landroid/telephony/TelephonyManager;->getSimSerialNumber()Ljava/lang/String; |
action_result.data.\*.analysis.androguard.functionalities.iccid.\*.method | string | | obtainTelephonyIds |
action_result.data.\*.analysis.androguard.functionalities.imei.\*.class | string | | Lafo; |
action_result.data.\*.analysis.androguard.functionalities.imei.\*.code | string | | invoke-virtual v0, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String; |
action_result.data.\*.analysis.androguard.functionalities.imei.\*.method | string | | e |
action_result.data.\*.analysis.androguard.functionalities.imsi.\*.class | string | | Lafo; |
action_result.data.\*.analysis.androguard.functionalities.imsi.\*.code | string | | invoke-virtual v0, Landroid/telephony/TelephonyManager;->getSubscriberId()Ljava/lang/String; |
action_result.data.\*.analysis.androguard.functionalities.imsi.\*.method | string | | f |
action_result.data.\*.analysis.androguard.functionalities.installedapplications.\*.class | string | | Lcom/my/target/core/parsers/b; |
action_result.data.\*.analysis.androguard.functionalities.installedapplications.\*.code | string | | invoke-virtual v0, v1, Landroid/content/pm/PackageManager;->getInstalledApplications(I)Ljava/util/List; |
action_result.data.\*.analysis.androguard.functionalities.installedapplications.\*.method | string | | a |
action_result.data.\*.analysis.androguard.functionalities.mcc.\*.class | string | | Ladp; |
action_result.data.\*.analysis.androguard.functionalities.mcc.\*.code | string | | invoke-virtual v0, Landroid/telephony/TelephonyManager;->getNetworkOperator()Ljava/lang/String; |
action_result.data.\*.analysis.androguard.functionalities.mcc.\*.method | string | | f |
action_result.data.\*.analysis.androguard.functionalities.phonecall.\*.class | string | | Lair; |
action_result.data.\*.analysis.androguard.functionalities.phonecall.\*.code | string | | const-string v1, 'android.intent.action.CALL' |
action_result.data.\*.analysis.androguard.functionalities.phonecall.\*.method | string | | a |
action_result.data.\*.analysis.androguard.functionalities.phonenumber.\*.class | string | | Lafo; |
action_result.data.\*.analysis.androguard.functionalities.phonenumber.\*.code | string | | invoke-virtual v0, Landroid/telephony/TelephonyManager;->getLine1Number()Ljava/lang/String; |
action_result.data.\*.analysis.androguard.functionalities.phonenumber.\*.method | string | | d |
action_result.data.\*.analysis.androguard.functionalities.runbinary.\*.class | string | | Laay; |
action_result.data.\*.analysis.androguard.functionalities.runbinary.\*.code | string | | invoke-static Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime; |
action_result.data.\*.analysis.androguard.functionalities.runbinary.\*.method | string | | a |
action_result.data.\*.analysis.androguard.functionalities.serialno.\*.class | string | | Lafo; |
action_result.data.\*.analysis.androguard.functionalities.serialno.\*.code | string | | const-string v3, 'ro.serialno' |
action_result.data.\*.analysis.androguard.functionalities.serialno.\*.method | string | | <clinit> |
action_result.data.\*.analysis.androguard.functionalities.socket.\*.class | string | | Labv; |
action_result.data.\*.analysis.androguard.functionalities.socket.\*.code | string | | invoke-virtual v11, Ljava/net/URL;->openConnection()Ljava/net/URLConnection; |
action_result.data.\*.analysis.androguard.functionalities.socket.\*.method | string | | a |
action_result.data.\*.analysis.androguard.functionalities.ssl.\*.class | string | | La; |
action_result.data.\*.analysis.androguard.functionalities.ssl.\*.code | string | | const-string v0, 'https://www.test.us/' |
action_result.data.\*.analysis.androguard.functionalities.ssl.\*.method | string | | b |
action_result.data.\*.analysis.androguard.main_activity | string | | com.test.mini.abc.Browser |
action_result.data.\*.analysis.androguard.max_sdk_version | string | | |
action_result.data.\*.analysis.androguard.min_sdk_version | numeric | | 16 |
action_result.data.\*.analysis.androguard.new_permissions | string | | com.test.abc.native.permission.C2D_MESSAGE |
action_result.data.\*.analysis.androguard.package_name | string | | com.test.abc.native |
action_result.data.\*.analysis.androguard.permissions | string | | android.permission.NFC |
action_result.data.\*.analysis.androguard.providers | string | | com.test.android.news.newsfeed.internal.cache.NewsfeedContentProvider |
action_result.data.\*.analysis.androguard.receivers | string | | com.test.abc.gcm.GcmBroadcastReceiver |
action_result.data.\*.analysis.androguard.services | string | | com.test.abc.ping.SyncAuthenticatorService |
action_result.data.\*.analysis.androguard.signature_name | string | | META-INF/ANDROID.RSA |
action_result.data.\*.analysis.androguard.target_sdk_version | numeric | | 25 |
action_result.data.\*.analysis.androguard.urls | string | `url` | https://www.test.us/ |
action_result.data.\*.analysis.androguard.version_code | string | | 321123747 |
action_result.data.\*.analysis.androguard.wearable | boolean | | True False |
action_result.data.\*.analysis.cuckoo.category | string | | file |
action_result.data.\*.analysis.cuckoo.file.crc32 | string | | D7FC7959 |
action_result.data.\*.analysis.cuckoo.file.md5 | string | `md5` | testfa2440d3da26b02ae03b9566test |
action_result.data.\*.analysis.cuckoo.file.name | string | | |
action_result.data.\*.analysis.cuckoo.file.path | string | | |
action_result.data.\*.analysis.cuckoo.file.sha1 | string | `sha1` | test2e8a9fb24546bdd04006f62027c4ab5btest |
action_result.data.\*.analysis.cuckoo.file.sha256 | string | `sha256` | test46ada7896b0c93a7a8741f3dbe3135e39b4b07100328b3a4c23b9bb3test |
action_result.data.\*.analysis.cuckoo.file.sha512 | string | | testbfb445d2fb7087732be295ee72267b4dcd76803ef38a90af62d9e8ae94c34a2302b2d1fc19bc0cbaf1926f26cf63f4dd7ecd2c949c419485d6f7708atest |
action_result.data.\*.analysis.cuckoo.file.size | numeric | | 9326031 |
action_result.data.\*.analysis.cuckoo.file.ssdeep | string | | 196608:kmu71DmUnRIeDuhTA9UZYpO65cQ0pRB5YOPYzG6roP8H9a:kmu71DlnRI80k2ZYpOWh0pH55PYhro0I |
action_result.data.\*.analysis.cuckoo.file.type | string | | Zip archive data |
action_result.data.\*.analysis.cuckoo.file_id | string | | |
action_result.data.\*.analysis.cuckoo.target.category | string | | file |
action_result.data.\*.analysis.cuckoo.target.file.crc32 | string | | 5BCCD162 |
action_result.data.\*.analysis.cuckoo.target.file.md5 | string | `md5` | testf1954c84f386554b741f5737test |
action_result.data.\*.analysis.cuckoo.target.file.sha1 | string | `sha1` | test294cd5bac77e93e41493bd69b42705e2test |
action_result.data.\*.analysis.cuckoo.target.file.sha256 | string | `sha256` | testa95ec1d9ee65ad14654fd4c4095e3c71fe5b4064fe8b9f6dc28478aftest |
action_result.data.\*.analysis.cuckoo.target.file.sha512 | string | | test989f8d8a4726bbc8ef61bbc73a855461d4897c2c43cdacd847f3901069d8ac230e6c80da67525e0ed94e3f8449f56520a7a6e143f8314ca08671308ctest |
action_result.data.\*.analysis.cuckoo.target.file.size | numeric | | 7544622 |
action_result.data.\*.analysis.cuckoo.target.file.ssdeep | string | | 196608:XX3GmbVoah5KRFtOHuPtEpT2q0XlfoJ82lCIOYb7hoI:2mbrh5M0HuPST2RVfQ8NIOGj |
action_result.data.\*.analysis.droidbox | string | | |
action_result.data.\*.analysis.droidbox.cryptousage.\*.algorithm | string | | base64_decode |
action_result.data.\*.analysis.droidbox.cryptousage.\*.data | string | | |
action_result.data.\*.analysis.droidbox.cryptousage.\*.processname | string | | eu.toralarm.toralarm_wm |
action_result.data.\*.analysis.droidbox.cryptousage.\*.tid | numeric | | 5133 |
action_result.data.\*.analysis.droidbox.cryptousage.\*.time | numeric | | 123.2289459705353 |
action_result.data.\*.analysis.droidbox.dexclass.\*.path | string | | /data/app/io.selendroid.testapp-1.apk |
action_result.data.\*.analysis.droidbox.dexclass.\*.pid | numeric | | 843 |
action_result.data.\*.analysis.droidbox.dexclass.\*.processname | string | | io.selendroid.testapp |
action_result.data.\*.analysis.droidbox.dexclass.\*.tid | numeric | | 1073870640 |
action_result.data.\*.analysis.droidbox.dexclass.\*.time | numeric | | 0.212098 |
action_result.data.\*.analysis.droidbox.dns.\*.domain | string | | rules.addapptr.com |
action_result.data.\*.analysis.droidbox.dns.\*.hostname | string | | rules.addapptr.com |
action_result.data.\*.analysis.droidbox.dns.\*.ip | string | | 151.80.27.93 |
action_result.data.\*.analysis.droidbox.filesdeleted.\*.name | string | | /data/app/com.test.app860056677872.rr-M42In0rnQNzdiDmPkpQy0A==/base.apk.x86_64.flock |
action_result.data.\*.analysis.droidbox.filesdeleted.\*.pid | numeric | `pid` | 4248 |
action_result.data.\*.analysis.droidbox.filesdeleted.\*.processname | string | | com.test.app860056677872.rr |
action_result.data.\*.analysis.droidbox.filesdeleted.\*.tid | numeric | | 4248 |
action_result.data.\*.analysis.droidbox.filesdeleted.\*.time | numeric | | 121.2224400043488 |
action_result.data.\*.analysis.droidbox.filesopen.\*.name | string | | /proc/self/cmdline |
action_result.data.\*.analysis.droidbox.filesopen.\*.pid | numeric | `pid` | 4248 |
action_result.data.\*.analysis.droidbox.filesopen.\*.processname | string | | com.test.app860056677872.rr |
action_result.data.\*.analysis.droidbox.filesopen.\*.tid | numeric | | 4248 |
action_result.data.\*.analysis.droidbox.filesopen.\*.time | numeric | | 121.2202398777008 |
action_result.data.\*.analysis.droidbox.filesread.\*.data | string | | |
action_result.data.\*.analysis.droidbox.filesread.\*.name | string | | /data/app/io.selendroid.testapp-1.apk |
action_result.data.\*.analysis.droidbox.filesread.\*.pid | numeric | `pid` | 4248 |
action_result.data.\*.analysis.droidbox.filesread.\*.processname | string | | com.mobeasyapp.app860056677872.rr |
action_result.data.\*.analysis.droidbox.filesread.\*.tid | numeric | | 4248 |
action_result.data.\*.analysis.droidbox.filesread.\*.time | numeric | | 121.220575094223 |
action_result.data.\*.analysis.droidbox.fileswritten.\*.data | string | | |
action_result.data.\*.analysis.droidbox.fileswritten.\*.name | string | | /data/user/0/com.test.app860056677872.rr/files/audience_network.dex |
action_result.data.\*.analysis.droidbox.fileswritten.\*.pid | numeric | `pid` | 4248 |
action_result.data.\*.analysis.droidbox.fileswritten.\*.processname | string | | com.test.app860056677872.rr |
action_result.data.\*.analysis.droidbox.fileswritten.\*.tid | numeric | | 5159 |
action_result.data.\*.analysis.droidbox.fileswritten.\*.time | numeric | | 121.2951688766479 |
action_result.data.\*.analysis.droidbox.libraries.\*.name | string | | monochrome_base |
action_result.data.\*.analysis.droidbox.libraries.\*.pid | numeric | | 5133 |
action_result.data.\*.analysis.droidbox.libraries.\*.processname | string | | eu.toralarm.toralarm_wm |
action_result.data.\*.analysis.droidbox.libraries.\*.tid | numeric | | 5133 |
action_result.data.\*.analysis.droidbox.libraries.\*.time | numeric | | 122.8014578819275 |
action_result.data.\*.analysis.droidbox.recvnet.\*.data | string | | 1603030058 |
action_result.data.\*.analysis.droidbox.recvnet.\*.pid | numeric | | 5133 |
action_result.data.\*.analysis.droidbox.recvnet.\*.processname | string | | eu.toralarm.toralarm_wm |
action_result.data.\*.analysis.droidbox.recvnet.\*.srchost | string | | 54.36.175.146 |
action_result.data.\*.analysis.droidbox.recvnet.\*.srcport | numeric | | 443 |
action_result.data.\*.analysis.droidbox.recvnet.\*.tid | numeric | | 6224 |
action_result.data.\*.analysis.droidbox.recvnet.\*.time | numeric | | 124.5965847969055 |
action_result.data.\*.analysis.droidbox.sendnet.\*.data | string | | |
action_result.data.\*.analysis.droidbox.sendnet.\*.desthost | string | | 185.86.138.16 |
action_result.data.\*.analysis.droidbox.sendnet.\*.destport | numeric | | 80 |
action_result.data.\*.analysis.droidbox.sendnet.\*.pid | numeric | | 5133 |
action_result.data.\*.analysis.droidbox.sendnet.\*.processname | string | | eu.toralarm.toralarm_wm |
action_result.data.\*.analysis.droidbox.sendnet.\*.tid | numeric | | 6239 |
action_result.data.\*.analysis.droidbox.sendnet.\*.time | numeric | | 125.5912230014801 |
action_result.data.\*.analysis.scanning_date | string | | 2018-01-04T22:15:07.627000 |
action_result.data.\*.analysis.sha256 | string | `sha256` | testa95ec1d9ee65ad14654fd4c4095e3c71fe5b4064fe8b9f6dc28478aftest |
action_result.data.\*.analysis.status | string | | analyzed |
action_result.data.\*.overview.analyzed | boolean | | True False |
action_result.data.\*.overview.app | string | | Test app |
action_result.data.\*.overview.comments_count | numeric | | 0 |
action_result.data.\*.overview.company | string | | Test Software ASA |
action_result.data.\*.overview.corrupted | boolean | | True False |
action_result.data.\*.overview.created_at | string | | 2022-06-13T10:32:12.772734+02:00 |
action_result.data.\*.overview.created_on | numeric | | 1515099685 |
action_result.data.\*.overview.detected | boolean | | True False |
action_result.data.\*.overview.displayed_version | string | | 32.0.2254.123747 |
action_result.data.\*.overview.id | string | | Lv8ydaXWQ4WOEQ3q |
action_result.data.\*.overview.image | string | `url` | https://test.abc.com/media/apk_images/2022/06/13/logo_o8aYRh9.png |
action_result.data.\*.overview.is_apk | boolean | | True False |
action_result.data.\*.overview.is_corrupted | boolean | | False True |
action_result.data.\*.overview.is_detected | boolean | | False True |
action_result.data.\*.overview.is_dynamic_analyzed | boolean | | True False |
action_result.data.\*.overview.is_installed | boolean | | False True |
action_result.data.\*.overview.is_static_analyzed | boolean | | True False |
action_result.data.\*.overview.is_trusted | boolean | | False True |
action_result.data.\*.overview.last_yara_analysis_at | string | | 2022-06-13T10:52:46.967913+02:00 |
action_result.data.\*.overview.matches_count | numeric | | 1 |
action_result.data.\*.overview.md5 | string | `md5` | 9b57f1954c84f386554b741ftesttest |
action_result.data.\*.overview.on_devices | boolean | | True False |
action_result.data.\*.overview.package_name | string | | com.test.mini.native |
action_result.data.\*.overview.rating | numeric | | 0 |
action_result.data.\*.overview.repo | string | | |
action_result.data.\*.overview.sha1 | string | `sha1` | testtestd5bac77e93e41493bd69b427testtest |
action_result.data.\*.overview.sha256 | string | `sha256` | testtest1d9ee65ad14654fd4c4095e3c71fe5b4064fe8b9f6dc284testtest |
action_result.data.\*.overview.size | numeric | | 7544622 |
action_result.data.\*.overview.stored | boolean | | True False |
action_result.data.\*.overview.tags | string | | bad-signed |
action_result.data.\*.overview.trusted | boolean | | True False |
action_result.data.\*.overview.updated_at | string | | 2022-06-13T10:32:12.772757+02:00 |
action_result.data.\*.overview.url | string | `url` | https://test.abc.com/apks/test46ada7896b0c93a7a8741f3dbe3135e39b4b07100328b3a4c23b9bb3test/ |
action_result.data.\*.overview.version | string | | 2 |
action_result.data.\*.overview.votes_count | numeric | | 0 |
action_result.summary.analysis_complete | boolean | | True False |
action_result.summary.sha256 | string | `sha256` | testtestc1d9ee65ad14654fd4c4095e3c71fe5b4064fe8b9f6dc284testtest |
action_result.message | string | | Successfully retrieved overview and analysis |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get report'

Query for results of an already completed detonation

Type: **investigate** <br>
Read only: **True**

Either the <b>sha256</b> or <b>vault_id</b> should be specified. If both are specified, the <b>vault_id</b> parameter will be used. You do not need to be the one who detonated a file to retrieve a report. As long as you know the sha256 (or, have the file in the vault) of the APK you want to analyze, you could run this action. The <b>attempts</b> parameter is how many times this action will poll for analysis results. By default, this number is only 1. If you are polling after <b>detonate file</b> timed out, then you will want to increase this to a higher number. There will be a 30 second interval between each polling attempt.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sha256** | optional | SHA256 hash of file to get analysis of | string | `sha256` |
**vault_id** | optional | Vault ID, will check if there is an existing report for this file | string | `vault id` `sha1` |
**attempts** | optional | Number of attempts to make while polling | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.attempts | numeric | | 10 |
action_result.parameter.sha256 | string | `sha256` | testa95ec1d9ee65ad14654fd4c4095e3c71fe5b4064fe8b9f6dc28478aftest |
action_result.parameter.vault_id | string | `vault id` `sha1` | |
action_result.data.\*.analysis.androguard.activities | string | | com.test.msdk.shell.MVActivity |
action_result.data.\*.analysis.androguard.androidtv | boolean | | True False |
action_result.data.\*.analysis.androguard.api_key.com::startapp::sdk::APPLICATION_ID | string | | |
action_result.data.\*.analysis.androguard.api_key.com::startapp::sdk::RETURN_ADS_ENABLED | string | | true |
action_result.data.\*.analysis.androguard.api_key.metrica:api:level | string | | 62 |
action_result.data.\*.analysis.androguard.api_key.metrica:configuration:api:level | string | | 1 |
action_result.data.\*.analysis.androguard.api_key.required_amazon_package:com::amazon::application::compatibility::enforcer::sdk::library | string | | 19000 |
action_result.data.\*.analysis.androguard.api_key.required_amazon_package:com::amazon::device::messaging::sdk::library | string | | 2074700 |
action_result.data.\*.analysis.androguard.app_name | string | | Test app |
action_result.data.\*.analysis.androguard.certificate.issuerDN | string | | /C=NO/ST=Oslo/L=Oslo/O=Opera Software ASA/OU=Opera Mini/CN=Opera Android CA |
action_result.data.\*.analysis.androguard.certificate.not_after | string | | May 25 08:27:16 2114 GMT |
action_result.data.\*.analysis.androguard.certificate.not_before | string | | Jun 18 08:27:16 2014 GMT |
action_result.data.\*.analysis.androguard.certificate.serial | string | `sha1` | testtestE07403744EF8827071A939D3testtest |
action_result.data.\*.analysis.androguard.certificate.sha1 | string | `sha1` | testtestE07403744EF8827071A939D3testtest |
action_result.data.\*.analysis.androguard.certificate.subjectDN | string | | /C=NO/ST=Oslo/L=Oslo/O=Opera Software ASA/OU=Opera Mini/CN=Opera Android CA |
action_result.data.\*.analysis.androguard.cordova | string | | |
action_result.data.\*.analysis.androguard.dexes.classes.sha256 | string | `sha256` | testtest45822f127329747ebc545fec8ca33301a1416a8e0e714e0ctesttest |
action_result.data.\*.analysis.androguard.dexes.classes.ssdeep | string | | 98304:ncDdVScJfr4RBrv2yP+KdFi+mNUsQBbaju6hEeRxQ:ncp0wfr4RBrv2yP+KdY+iUsDtesttest |
action_result.data.\*.analysis.androguard.dexes.classes2.sha256 | string | `sha256` | 7f857344077ffc64899cf60bdf1dbef9776250d55f803e9a23831da7testtest |
action_result.data.\*.analysis.androguard.dexes.classes2.ssdeep | string | | 24576:Zmh4ZRdgplwdv4X5l5mE1RQ32WpQMzMAlgHz87OUsDvp8+UTVNFkxApmkwOvS:bRQlG4X8P2WpQ0MAlgTtesttest |
action_result.data.\*.analysis.androguard.displayed_version | string | | 32.0.2254.123747 |
action_result.data.\*.analysis.androguard.filters | string | | android.intent.action.PACKAGE_REMOVED |
action_result.data.\*.analysis.androguard.functionalities.SMS.\*.class | string | | Lcom/admarvel/android/ads/Utils; |
action_result.data.\*.analysis.androguard.functionalities.SMS.\*.code | string | | const-string v5, 'sms_body' |
action_result.data.\*.analysis.androguard.functionalities.SMS.\*.method | string | | a |
action_result.data.\*.analysis.androguard.functionalities.ads.\*.class | string | | Laje$3; |
action_result.data.\*.analysis.androguard.functionalities.ads.\*.code | string | | const-string v5, 'AdMob error code: ' |
action_result.data.\*.analysis.androguard.functionalities.ads.\*.method | string | | onAdFailedToLoad |
action_result.data.\*.analysis.androguard.functionalities.camera.\*.class | string | | Lcom/opera/android/custom_views/GenericCameraView; |
action_result.data.\*.analysis.androguard.functionalities.camera.\*.code | string | | invoke-virtual v0, v1, Landroid/hardware/Camera;->setPreviewDisplay(Landroid/view/SurfaceHolder;)V |
action_result.data.\*.analysis.androguard.functionalities.camera.\*.method | string | | b |
action_result.data.\*.analysis.androguard.functionalities.crypto.\*.class | string | | Labe; |
action_result.data.\*.analysis.androguard.functionalities.crypto.\*.code | string | | invoke-virtual v0, v1, Ljava/security/MessageDigest;->digest(\[B)\[B |
action_result.data.\*.analysis.androguard.functionalities.crypto.\*.method | string | | e |
action_result.data.\*.analysis.androguard.functionalities.dynamicbroadcastreceiver.\*.class | string | | Labv; |
action_result.data.\*.analysis.androguard.functionalities.dynamicbroadcastreceiver.\*.code | string | | invoke-virtual v1, v2, v3, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver; Landroid/content/IntentFilter;)Landroid/content/Intent; |
action_result.data.\*.analysis.androguard.functionalities.dynamicbroadcastreceiver.\*.method | string | | g |
action_result.data.\*.analysis.androguard.functionalities.iccid.\*.class | string | | Lcom/apprupt/sdk/CvAppInfo; |
action_result.data.\*.analysis.androguard.functionalities.iccid.\*.code | string | | invoke-virtual v0, Landroid/telephony/TelephonyManager;->getSimSerialNumber()Ljava/lang/String; |
action_result.data.\*.analysis.androguard.functionalities.iccid.\*.method | string | | obtainTelephonyIds |
action_result.data.\*.analysis.androguard.functionalities.imei.\*.class | string | | Lafo; |
action_result.data.\*.analysis.androguard.functionalities.imei.\*.code | string | | invoke-virtual v0, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String; |
action_result.data.\*.analysis.androguard.functionalities.imei.\*.method | string | | e |
action_result.data.\*.analysis.androguard.functionalities.imsi.\*.class | string | | Lafo; |
action_result.data.\*.analysis.androguard.functionalities.imsi.\*.code | string | | invoke-virtual v0, Landroid/telephony/TelephonyManager;->getSubscriberId()Ljava/lang/String; |
action_result.data.\*.analysis.androguard.functionalities.imsi.\*.method | string | | f |
action_result.data.\*.analysis.androguard.functionalities.installedapplications.\*.class | string | | Lcom/my/target/core/parsers/b; |
action_result.data.\*.analysis.androguard.functionalities.installedapplications.\*.code | string | | invoke-virtual v0, v1, Landroid/content/pm/PackageManager;->getInstalledApplications(I)Ljava/util/List; |
action_result.data.\*.analysis.androguard.functionalities.installedapplications.\*.method | string | | a |
action_result.data.\*.analysis.androguard.functionalities.mcc.\*.class | string | | Ladp; |
action_result.data.\*.analysis.androguard.functionalities.mcc.\*.code | string | | invoke-virtual v0, Landroid/telephony/TelephonyManager;->getNetworkOperator()Ljava/lang/String; |
action_result.data.\*.analysis.androguard.functionalities.mcc.\*.method | string | | f |
action_result.data.\*.analysis.androguard.functionalities.phonecall.\*.class | string | | Lair; |
action_result.data.\*.analysis.androguard.functionalities.phonecall.\*.code | string | | const-string v1, 'android.intent.action.CALL' |
action_result.data.\*.analysis.androguard.functionalities.phonecall.\*.method | string | | a |
action_result.data.\*.analysis.androguard.functionalities.phonenumber.\*.class | string | | Lafo; |
action_result.data.\*.analysis.androguard.functionalities.phonenumber.\*.code | string | | invoke-virtual v0, Landroid/telephony/TelephonyManager;->getLine1Number()Ljava/lang/String; |
action_result.data.\*.analysis.androguard.functionalities.phonenumber.\*.method | string | | d |
action_result.data.\*.analysis.androguard.functionalities.runbinary.\*.class | string | | Laay; |
action_result.data.\*.analysis.androguard.functionalities.runbinary.\*.code | string | | invoke-static Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime; |
action_result.data.\*.analysis.androguard.functionalities.runbinary.\*.method | string | | a |
action_result.data.\*.analysis.androguard.functionalities.serialno.\*.class | string | | Lafo; |
action_result.data.\*.analysis.androguard.functionalities.serialno.\*.code | string | | const-string v3, 'ro.serialno' |
action_result.data.\*.analysis.androguard.functionalities.serialno.\*.method | string | | <clinit> |
action_result.data.\*.analysis.androguard.functionalities.socket.\*.class | string | | Labv; |
action_result.data.\*.analysis.androguard.functionalities.socket.\*.code | string | | invoke-virtual v11, Ljava/net/URL;->openConnection()Ljava/net/URLConnection; |
action_result.data.\*.analysis.androguard.functionalities.socket.\*.method | string | | a |
action_result.data.\*.analysis.androguard.functionalities.ssl.\*.class | string | | La; |
action_result.data.\*.analysis.androguard.functionalities.ssl.\*.code | string | | const-string v0, 'https://www.test.us/' |
action_result.data.\*.analysis.androguard.functionalities.ssl.\*.method | string | | b |
action_result.data.\*.analysis.androguard.main_activity | string | | com.test.mini.abc.Browser |
action_result.data.\*.analysis.androguard.max_sdk_version | string | | |
action_result.data.\*.analysis.androguard.min_sdk_version | numeric | | 16 |
action_result.data.\*.analysis.androguard.new_permissions | string | | com.test.abc.native.permission.C2D_MESSAGE |
action_result.data.\*.analysis.androguard.package_name | string | | com.test.abc.native |
action_result.data.\*.analysis.androguard.permissions | string | | android.permission.NFC |
action_result.data.\*.analysis.androguard.providers | string | | com.opera.android.news.newsfeed.internal.cache.NewsfeedContentProvider |
action_result.data.\*.analysis.androguard.receivers | string | | com.test.abc.gcm.GcmBroadcastReceiver |
action_result.data.\*.analysis.androguard.services | string | | com.test.abc.ping.SyncAuthenticatorService |
action_result.data.\*.analysis.androguard.signature_name | string | | META-INF/ANDROID.RSA |
action_result.data.\*.analysis.androguard.target_sdk_version | numeric | | 25 |
action_result.data.\*.analysis.androguard.urls | string | `url` | https://www.test.us/ |
action_result.data.\*.analysis.androguard.version_code | string | | 321123747 |
action_result.data.\*.analysis.androguard.wearable | boolean | | True False |
action_result.data.\*.analysis.cuckoo.category | string | | file |
action_result.data.\*.analysis.cuckoo.file.crc32 | string | | D7FC7959 |
action_result.data.\*.analysis.cuckoo.file.md5 | string | `md5` | testfa2440d3da26b02ae03b9566test |
action_result.data.\*.analysis.cuckoo.file.name | string | | |
action_result.data.\*.analysis.cuckoo.file.path | string | | |
action_result.data.\*.analysis.cuckoo.file.sha1 | string | `sha1` | test2e8a9fb24546bdd04006f62027c4ab5btest |
action_result.data.\*.analysis.cuckoo.file.sha256 | string | `sha256` | test46ada7896b0c93a7a8741f3dbe3135e39b4b07100328b3a4c23b9bb3test |
action_result.data.\*.analysis.cuckoo.file.sha512 | string | | testbfb445d2fb7087732be295ee72267b4dcd76803ef38a90af62d9e8ae94c34a2302b2d1fc19bc0cbaf1926f26cf63f4dd7ecd2c949c419485d6f7708atest |
action_result.data.\*.analysis.cuckoo.file.size | numeric | | 9326031 |
action_result.data.\*.analysis.cuckoo.file.ssdeep | string | | 196608:kmu71DmUnRIeDuhTA9UZYpO65cQ0pRB5YOPYzG6roP8H9a:kmu71DlnRI80k2ZYpOWh0pH55PYhro0I |
action_result.data.\*.analysis.cuckoo.file.type | string | | Zip archive data |
action_result.data.\*.analysis.cuckoo.file_id | string | | |
action_result.data.\*.analysis.cuckoo.target.category | string | | file |
action_result.data.\*.analysis.cuckoo.target.file.crc32 | string | | 5BCCD162 |
action_result.data.\*.analysis.cuckoo.target.file.md5 | string | `md5` | testf1954c84f386554b741f5737test |
action_result.data.\*.analysis.cuckoo.target.file.sha1 | string | `sha1` | test294cd5bac77e93e41493bd69b42705e2test |
action_result.data.\*.analysis.cuckoo.target.file.sha256 | string | `sha256` | testa95ec1d9ee65ad14654fd4c4095e3c71fe5b4064fe8b9f6dc28478aftest |
action_result.data.\*.analysis.cuckoo.target.file.sha512 | string | | test989f8d8a4726bbc8ef61bbc73a855461d4897c2c43cdacd847f3901069d8ac230e6c80da67525e0ed94e3f8449f56520a7a6e143f8314ca08671308ctest |
action_result.data.\*.analysis.cuckoo.target.file.size | numeric | | 7544622 |
action_result.data.\*.analysis.cuckoo.target.file.ssdeep | string | | 196608:XX3GmbVoah5KRFtOHuPtEpT2q0XlfoJ82lCIOYb7hoI:2mbrh5M0HuPST2RVfQ8NIOGj |
action_result.data.\*.analysis.droidbox | string | | |
action_result.data.\*.analysis.droidbox.cryptousage.\*.algorithm | string | | base64_decode |
action_result.data.\*.analysis.droidbox.cryptousage.\*.data | string | | |
action_result.data.\*.analysis.droidbox.cryptousage.\*.processname | string | | eu.toralarm.toralarm_wm |
action_result.data.\*.analysis.droidbox.cryptousage.\*.tid | numeric | | 5133 |
action_result.data.\*.analysis.droidbox.cryptousage.\*.time | numeric | | 123.2289459705353 |
action_result.data.\*.analysis.droidbox.dexclass.\*.path | string | | /data/app/io.selendroid.testapp-1.apk |
action_result.data.\*.analysis.droidbox.dexclass.\*.pid | numeric | | 843 |
action_result.data.\*.analysis.droidbox.dexclass.\*.processname | string | | io.selendroid.testapp |
action_result.data.\*.analysis.droidbox.dexclass.\*.tid | numeric | | 1073870640 |
action_result.data.\*.analysis.droidbox.dexclass.\*.time | numeric | | 0.212098 |
action_result.data.\*.analysis.droidbox.dns.\*.domain | string | | rules.addapptr.com |
action_result.data.\*.analysis.droidbox.dns.\*.hostname | string | | rules.addapptr.com |
action_result.data.\*.analysis.droidbox.dns.\*.ip | string | | 151.80.27.93 |
action_result.data.\*.analysis.droidbox.filesdeleted.\*.name | string | | /data/app/com.test.app860056677872.rr-M42In0rnQNzdiDmPkpQy0A==/base.apk.x86_64.flock |
action_result.data.\*.analysis.droidbox.filesdeleted.\*.pid | numeric | `pid` | 4248 |
action_result.data.\*.analysis.droidbox.filesdeleted.\*.processname | string | | com.test.app860056677872.rr |
action_result.data.\*.analysis.droidbox.filesdeleted.\*.tid | numeric | | 4248 |
action_result.data.\*.analysis.droidbox.filesdeleted.\*.time | numeric | | 121.2224400043488 |
action_result.data.\*.analysis.droidbox.filesopen.\*.name | string | | /proc/self/cmdline |
action_result.data.\*.analysis.droidbox.filesopen.\*.pid | numeric | `pid` | 4248 |
action_result.data.\*.analysis.droidbox.filesopen.\*.processname | string | | com.test.app860056677872.rr |
action_result.data.\*.analysis.droidbox.filesopen.\*.tid | numeric | | 4248 |
action_result.data.\*.analysis.droidbox.filesopen.\*.time | numeric | | 121.2202398777008 |
action_result.data.\*.analysis.droidbox.filesread.\*.data | string | | |
action_result.data.\*.analysis.droidbox.filesread.\*.name | string | | /data/app/io.selendroid.testapp-1.apk |
action_result.data.\*.analysis.droidbox.filesread.\*.pid | numeric | `pid` | 4248 |
action_result.data.\*.analysis.droidbox.filesread.\*.processname | string | | com.mobeasyapp.app860056677872.rr |
action_result.data.\*.analysis.droidbox.filesread.\*.tid | numeric | | 4248 |
action_result.data.\*.analysis.droidbox.filesread.\*.time | numeric | | 121.220575094223 |
action_result.data.\*.analysis.droidbox.fileswritten.\*.data | string | | |
action_result.data.\*.analysis.droidbox.fileswritten.\*.name | string | | /data/user/0/com.test.app860056677872.rr/files/audience_network.dex |
action_result.data.\*.analysis.droidbox.fileswritten.\*.pid | numeric | `pid` | 4248 |
action_result.data.\*.analysis.droidbox.fileswritten.\*.processname | string | | com.test.app860056677872.rr |
action_result.data.\*.analysis.droidbox.fileswritten.\*.tid | numeric | | 5159 |
action_result.data.\*.analysis.droidbox.fileswritten.\*.time | numeric | | 121.2951688766479 |
action_result.data.\*.analysis.droidbox.libraries.\*.name | string | | monochrome_base |
action_result.data.\*.analysis.droidbox.libraries.\*.pid | numeric | | 5133 |
action_result.data.\*.analysis.droidbox.libraries.\*.processname | string | | eu.toralarm.toralarm_wm |
action_result.data.\*.analysis.droidbox.libraries.\*.tid | numeric | | 5133 |
action_result.data.\*.analysis.droidbox.libraries.\*.time | numeric | | 122.8014578819275 |
action_result.data.\*.analysis.droidbox.recvnet.\*.data | string | | 1603030058 |
action_result.data.\*.analysis.droidbox.recvnet.\*.pid | numeric | | 5133 |
action_result.data.\*.analysis.droidbox.recvnet.\*.processname | string | | eu.toralarm.toralarm_wm |
action_result.data.\*.analysis.droidbox.recvnet.\*.srchost | string | | 54.36.175.146 |
action_result.data.\*.analysis.droidbox.recvnet.\*.srcport | numeric | | 443 |
action_result.data.\*.analysis.droidbox.recvnet.\*.tid | numeric | | 6224 |
action_result.data.\*.analysis.droidbox.recvnet.\*.time | numeric | | 124.5965847969055 |
action_result.data.\*.analysis.droidbox.sendnet.\*.data | string | | |
action_result.data.\*.analysis.droidbox.sendnet.\*.desthost | string | | 185.86.138.16 |
action_result.data.\*.analysis.droidbox.sendnet.\*.destport | numeric | | 80 |
action_result.data.\*.analysis.droidbox.sendnet.\*.pid | numeric | | 5133 |
action_result.data.\*.analysis.droidbox.sendnet.\*.processname | string | | eu.toralarm.toralarm_wm |
action_result.data.\*.analysis.droidbox.sendnet.\*.tid | numeric | | 6239 |
action_result.data.\*.analysis.droidbox.sendnet.\*.time | numeric | | 125.5912230014801 |
action_result.data.\*.analysis.scanning_date | string | | 2018-01-04T22:15:07.627000 |
action_result.data.\*.analysis.sha256 | string | `sha256` | testa95ec1d9ee65ad14654fd4c4095e3c71fe5b4064fe8b9f6dc28478aftest |
action_result.data.\*.analysis.status | string | | analyzed |
action_result.data.\*.overview.analyzed | boolean | | True False |
action_result.data.\*.overview.app | string | | Test app |
action_result.data.\*.overview.comments_count | numeric | | 0 |
action_result.data.\*.overview.company | string | | Test Software ASA |
action_result.data.\*.overview.corrupted | boolean | | True False |
action_result.data.\*.overview.created_at | string | | 2022-06-13T10:32:12.772734+02:00 |
action_result.data.\*.overview.created_on | numeric | | 1515099685 |
action_result.data.\*.overview.detected | boolean | | True False |
action_result.data.\*.overview.displayed_version | string | | 32.0.2254.123747 |
action_result.data.\*.overview.id | string | | Lv8ydaXWQ4WOEQ3q |
action_result.data.\*.overview.image | string | `url` | https://test.abc.com/media/apk_images/2022/06/13/logo_o8aYRh9.png |
action_result.data.\*.overview.is_apk | boolean | | True False |
action_result.data.\*.overview.is_corrupted | boolean | | False True |
action_result.data.\*.overview.is_detected | boolean | | False True |
action_result.data.\*.overview.is_dynamic_analyzed | boolean | | True False |
action_result.data.\*.overview.is_installed | boolean | | False True |
action_result.data.\*.overview.is_static_analyzed | boolean | | True False |
action_result.data.\*.overview.is_trusted | boolean | | False True |
action_result.data.\*.overview.last_yara_analysis_at | string | | 2022-06-13T10:52:46.967913+02:00 |
action_result.data.\*.overview.matches_count | numeric | | 1 |
action_result.data.\*.overview.md5 | string | `md5` | 9b57f1954c84f386554b741ftesttest |
action_result.data.\*.overview.on_devices | boolean | | True False |
action_result.data.\*.overview.package_name | string | | com.test.mini.native |
action_result.data.\*.overview.rating | numeric | | 0 |
action_result.data.\*.overview.repo | string | | |
action_result.data.\*.overview.sha1 | string | `sha1` | testtestd5bac77e93e41493bd69b427testtest |
action_result.data.\*.overview.sha256 | string | `sha256` | testtest1d9ee65ad14654fd4c4095e3c71fe5b4064fe8b9f6dc284testtest |
action_result.data.\*.overview.size | numeric | | 7544622 |
action_result.data.\*.overview.stored | boolean | | True False |
action_result.data.\*.overview.tags | string | | bad-signed |
action_result.data.\*.overview.trusted | boolean | | True False |
action_result.data.\*.overview.updated_at | string | | 2022-06-13T10:32:12.772757+02:00 |
action_result.data.\*.overview.url | string | `url` | https://test.abc.com/apks/test46ada7896b0c93a7a8741f3dbe3135e39b4b07100328b3a4c23b9bb3test/ |
action_result.data.\*.overview.version | string | | 2 |
action_result.data.\*.overview.votes_count | numeric | | 0 |
action_result.summary.analysis_complete | boolean | | True False |
action_result.summary.sha256 | string | `sha256` | testtestc1d9ee65ad14654fd4c4095e3c71fe5b4064fe8b9f6dc284testtest |
action_result.message | string | | Successfully retrieved overview and analysis |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
