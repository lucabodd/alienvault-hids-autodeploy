# Alienvault infrastructure setup

This role prepare scanner and sensors hosts.

## Requirements

Maybe none.

## Role Variables

* *todo: we don't really have vars*

## Dependencies

* gantsign.golang: can be configured as per [here](https://github.com/gantsign/ansible-role-golang). We default to golang version is 1.13.

## Example Playbook

An example playbook could be:


```yaml

- hosts: scanners
  roles:
    - role: alienvault
      # could obv be configured in host/group_vars
      vars:
        node_type: scanner

- hosts: sensors
  roles:
    - role: alienvault
      # could obv be configured in host/group_vars
      vars:
        node_type: sensor

```

License
-------

XXX

Author Information
------------------

An optional section for the role authors to include contact information, or a website (HTML is not allowed).
