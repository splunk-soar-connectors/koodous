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
