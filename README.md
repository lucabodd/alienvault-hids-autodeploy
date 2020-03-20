# Alienvault-hids-autodeploy

Offering a golang program to automate ossec-hids deployment on an entire
subnet (or single host).
The program will be setting up an agent that allows hosts to connect to
alienvault sensors via port 1514 (UDP) and send system events.

## Scanners, sensors setup

Have an ansible inventory where you define scanners and sensors:

```ini
[scanners]
scanner_hostname

[sensors]
sensor1_hostname
sensor2_hostname
sensor3_hostname
```

then the playbook will configure nodes, based on current variables:

* *todo: we don't really have vars*
* golang installation details variables are as per [dependency role](https://github.com/gantsign/ansible-role-golang)

Should you wanna skip infrastructure setup, relevant tag is `infra_setup`.

More infos in [role README](roles/alienvault/README.md).

## Testing

Install molecule:

```shell
pip install --user --upgrade molecule
```

then from `roles/alienvault/` dir do `molecule test`. This spin three container and do the stuff.

todo: molecule's verification asserts.


## Usage

the program may run with the following flags:

```
Usage: Alienvault-hids-deploy [OPTIONS]
One ore more required flag has not been prodided.
Note that using less flag than defined could lead program into errors (not required flags are site-*).
Omit flags only if you are aware of what are you doin'
  -help
        prints this help message
  -no-copy-id
        Copy ssh public key to scanned assets. Set this flag if you store RSA public keys not in ~/.ssh/authorized_keys. If this flag is set to false password will be written CLEARTEXT in ansible inventory file
  -p string
        Specify on which ports SSH might be listening on (default "22")
  -sensor-ip string
        Sensor IP ossec-hids agents should connect to
  -sensor-port string
        Sensor SSH port (default "22")
  -site-lat string
        Override geolocation latitude discovery for a site
  -site-long string
        Override geolocation longitude discovery for a site
  -subnet-cidr string
        Specify subnet/host CIDR where to install ossec-hids agent

```
