# cis_security_hardening

## Table of Contents

1. [Description](#description)
2. [Security baseline](#security-baseline)
3. [CIS Benchmark Reference](#CIS-Benchmark-Reference)
4. [Setup - The basics of getting started with cis_security_hardening](#setup)
    * [What cis_security_hardening affects](#what-cis_security_hardening-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with cis_security_hardening](#beginning-with-cis_security_hardening)
    * [Cronjobs](#cronjobs)
5. [Usage](#usage)
6. [Reference](#reference)
7. [Limitations](#limitations)
    * [Auditd](#auditd)
    * [SELinux and Apparmor](#selinux-and-apparmor)
    * [Automatic reboot](#automatic-reboot)
    * [Suse SLES 12 and 15](#suse-sles-12-and-15)
8. [Credits](#credits)
9. [Development](#development)
10. [Changelog](#changelog)
11. [Contributors](#contributors)
12. [Warranty](#warranty)

## Description

Define a complete security baseline and monitor the baseline's rules. The definition of the baseline should be done in Hiera. The purpose of the module is to give the ability to setup a complete security baseline which not necessarily have to stick to industry security guides like the CIS benchmarks.

The *cis_security_hardening* module does not use bechmark numbers for the class names of the rules. These numbers change from OS version to OS version and even from benchmark version to benchmark version. One main purpose is to ensure this module can be extended by further security settings and monitorings without changing the code of this module. Therefore the module uses a generic interface to call classes implementing particular security baseline rules.

This module also has the ability to create compliance reports. The reports can be created as a Puppet fact uploaded to the Puppet Master or as a CSV file which will remain on the servers for later collection.

## Security baseline

A security baseline describes how servers in your environment are setup with a secure configuration. The baseline may be different for each server class like database servers, application or web servers.

A security baseline can be based on a CIS benchmark but can include more rules specific to your environment. But depending on server classes not all rules of a CIS benchmark will be used. Sometimes the benchmarks contain different ways to achieve a goal, e.g. with RedHat 8 you can use firewalld, iptables or nftables to setup a firewall. Surely it makes no sense to have all of them running in parallel. So it is your task to define a security baseline to define which tool to use or which settings to use.

> For this module level 1 and level 2 server tests from the CIS benchmarks below are taken into account. For the STIG benchmarks there's a third level `stig` available as STIG benchmarks are more strict than level 2 is.

## CIS Benchmark Reference

The code of this security hardening module is based on the following CIS Benchmarks:

| OS           | Benchmark version                                            | Version | Date       |
|--------------|--------------------------------------------------------------|---------|------------|
| Suse SLES 12 | CIS SUSE Linux Enterprise 12 Benchmark                       | 3.1.0   | 01-24-2022 |
| Suse SLES 15 | CIS SUSE Linux Enterprise 15 Benchmark                       | 1.1.1   | 09-17-2021 |
| RedHat 7     | CIS Red Hat Enterprise Linux 7 Benchmark                     | 3.1.1   | 05-21-2021 |
| RedHat 7     | CIS Red Hat Enterprise Linux 7 STIG Benchmark                | 2.0.0   | 11-29-2021 |
| RedHat 8     | CIS Red Hat Enterprise Linux 8 Benchmark                     | 2.0.0   | 02-23-2022 |
| RedHat 8     | CIS Red Hat Enterprise Linux 8 STIG Benchmark                | 1.0.0   | 11-12-2021 |
| CentOS 7     | CIS CentOS Linux 7 Benchmark                                 | 3.1.2   | 08-31-2021 |
| Ubuntu 18.04 | CIS Ubuntu Linux 18.04 LTS Benchmark                         | 2.0.1   | 01-03-2020 |
| Ubuntu 20.04 | CIS Ubuntu Linux 20.04 LTS Benchmark                         | 1.1.0   | 03-31-2021 |
| Ubuntu 20.04 | CIS Ubuntu Linux 20.04 LTS STIG Benchmark                    | 1.0.0   | 26.07.2021 |
| Debian 10    | CIS Debian Linux 10 Benchmark                                | 1.0.0   | 02-13-2020 |
| Alma Linux 8 | CIS Alma Linux OS 8 Benchmark                                | 2.0.0   | 05-31-2022 |
| Rocky Linux 8| CIS Rocky Linux 8 Benchmark                                  | 1.0.0   | 03-29-2022 |

The benchmarks can be found at [CIS Benchmarks Website](https://downloads.cisecurity.org/#/).

## Setup

It is highly recommended to have the complete security baseline definition written in Hiera definitions. This enables you to have different security baselines for groups of servers, environments or even special single servers.

### What cis_security_hardening affects

The *cis_security_hardening* module has a parameter `enforce` for each rule. If this parameter is set to true all necessary changes are made to make a server compliant to the security baseline rules. This can have severe impacts to the machines, especially if security settings are defined in a wrong way.
> Please test your settings before rolling out to production environments.

The module needs a base directory. The base directory `/usr/share/cis_security_hardening` is created by the module during the fist run. Some data is collected with cronjobs once a day as collecting this data is somewhat expensive and time consuming depending on the server size, e. g. searching als s-bit programs . Under the base directory there will be a directory `bin` where all scripts for gathering information are located.

This module creates a larger fact `cis_security_hardening` to have all required information for applying the rules. Some information is collected with cronjobs once a day as these jobs might run for a long time (e. g. searching filesystems for s-bit programs).

### Setup Requirements

The *cis_security_hardening* module needs several other Puppet modules. These modules are defined in the [metadata.json](https://github.com/tom-krieger/cis_security_hardening/blob/master/metadata.json) file and are all available at [Puppet Forge](https://forge.puppet.com/).

### Beginning with cis_security_hardening

The most easiest way to use the security baseline module is just calling the class or including the class.

```puppet
class { 'cis_security_hardening':
}
```

or

```puppet
include cis_security_hardening
```

The `data` folder contains example Hiera definitions for various operation systems.

### Cronjobs

Gathering information can sometime consume a lot of time. Gathering those facts during Puppet runs would have a significat impact on the time consumed by a Puppet run. Therefore some facts are only gathered once a day using cronjobs. The `cis_security_hardening` module installes the following cronjobs to collect information and provide the information to the fact scripts creating the `cis_security_hardening` fact.

#### Cron /etc/cron.d/sticky-world-writebale.cron

This cronjob searches for world writable files with sticky bit.

#### /etc/cron.d/auditd_priv_commands.cron

This cronjob searched privileged commands to be included into auditd rules.

## Usage

The most easiest way to use the security baseline module is just calling the class or including the class. The security baseline data has to be defined in a Hiera configuration file.

```puppet
class { 'cis_security_hardening':

}
```

or

```puppet
include ::cis_security_hardening
```

Hiera data:

```hiera
---
cis_security_hardening::profile: server
cis_security_hardening::level: "2"
cis_security_hardening::time_until_reboot: 60
cis_security_hardening::exclude_dirs_sticky_ww: []
cis_security_hardening::update_postrun_command: true
cis_security_hardening::fact_upload_command: "/usr/share/cis_security_hardening/bin/fact_upload.sh"
cis_security_hardening::auditd_dirs_to_include:
  - "/usr"
cis_security_hardening::verbose_logging: false

cis_security_hardening::rules::cramfs::enforce: true
cis_security_hardening::rules::squashfs::enforce: true
cis_security_hardening::rules::fat::enforce: false
cis_security_hardening::rules::udf::enforce: true
```

The `data` folder contains files named `*_param.yaml` which contain all configurable options for each benchmark. You also can look into the reference documentation.

## Reference

See [REFERENCE.md](https://github.com/tom-krieger/cis_security_hardening/blob/master/REFERENCE.md)

## Limitations

Currently the module is tested with RedHat 7, 8, CentOS 8, Suse SLES 12, Debian 10, Ubuntu 18.04 and Ubuntu 20.04. Other OSes may work but there's no guarantee. If you need your own rules please create Puppet modules and call them from the security baseline module. See [extend the security baseline](#extend-the-security-baseline).

More testing is needed as for every supported OS there are different setups in the wild and some of them might not be covered.

For a list of supported OSes please look into the `metadata.json` file.

### Auditd

Auditd is normally configured with immutable rules. This meens that changing rules will require a *reboot* to make the new rules effective.

### SELinux and Apparmor

SELinux and AppArmor are - if configured - activated while this module is applied. To make them effective a *reboot* is required.

### Automatic reboot

Automatic reboots might be *dangerous* as servers would be rebooted if one of the classes subscribed for reboot takes any action. But some changes need a reboot, e. g. enabling SELinux or changing auditd rules. As servers in production environments may not be rebooted you have to choose if you will allow reboots by settings a parameter *auto_reboot*. You can choose this for each rule triggering a reboot to be able to decide, which reboots are important enough to trigger an automatic reboot. The *auto_reboot* parameter is available for all rules which can trigger a reboot. Currently the following rules trigger reboots:

* auditd_init
* crypto_policy
* selinux_policy
* selinux_state

The default value for *auto_reboot* is `true` and can easily be changed by setting it to false in the Hier configuration of this module.

The global parameter `time_until_reboot` sets the waiting time until the reboot will be performed. On Linux systems you can cancel this reboot with the `shutdown -c` command. But keep in mind that canceling the reboot won't activate some changes.

Hiera example:

```hiera
---
cis_security_hardening::reboot_timeout: 120

cis_security_hardening::rules::selinux_policy::auto_reboot: true
```

### Suse SLES 12 and 15

The compliance rules have been implemented without or very limited testing. Please report problems or create pull requests to improve the Suse SLES compliance code.

### Issues with CISCAT scanner

* CISCAT scanner for Ubuntu 20.04 LTS STIG false positives:
  * reports a not correct configured TMOUT setting but running the check task from the benchmark reports PASSED.
  * reports that not all audit log files re not read or write-accessible by unauthorized users which seems to be caused by a `lost+found` directory with permissions 0700
  * reports that audit log directory is not set 0750 or more restrictive but it is 0750
  * reports that not all system command files are group-owned by root but the check searches for all files and not only these not having permissions /2000

## Credits

This project is highly inspired by the [fervid/secure_linux_cis](https://forge.puppet.com/fervid/secure_linux_cis) module from Puppet Forge and uses my [security_baseline](https://forge.puppet.com/modules/tomkrieger/security_baseline) module as basis.

## Development

Contributions are welcome in any form, pull requests, and issues should be filed via GitHub.

## Changelog

See [CHANGELOG.md](https://github.com/tom-krieger/cis_security_hardening/blob/master/CHANGELOG.md)

## Contributors

The list of contributors can be found at: [https://github.com/tom-krieger/cis_security_hardening/graphs/contributors](https://github.com/tom-krieger/cis_security_hardening/graphs/contributors).

## Warranty

This Puppet module is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the Apache 2.0 License for more details.
