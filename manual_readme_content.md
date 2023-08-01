[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2018-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Playbook Backward Compatibility

-   The parameters have been added in the below-existing action. Hence, it is requested to update
    existing playbooks created in the earlier versions of the app by re-inserting | modifying |
    deleting the corresponding action blocks.

      

    -   Detonate File - Below parameter have been added.

          

        -   'analysis type'
        -   'force yara analysis'

## Note:

If negative or zero value is passed in the 'attempts' parameter in 'detonate_file' and 'get_report'
action, it will be considered as 1.
