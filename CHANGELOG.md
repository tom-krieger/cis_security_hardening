# Changelog

All notable changes to this project will be documented in this file.

## Release 0.9.5

* added Debain 12 support (based on PPR #80)
* PR: 86 and 88: Replace legacy facts causing silent failures. Increase firewall dependency version. Add systemd to fixtures

## Release 0.9.4

* added puppet-systemd module as it's a dependency of the puppet-logrotate module
* added Debian 12 support (thanks the PRs)

## Release 0.9.3

* Fix fotr automaticq error reporting in Ubuntu 20.04:
  * use flag for package uninstallation
  * disable and mask service

## Release 0.9.2

* Updated to Ubuntu 20.04 benchmark version 2.0.1
* fix for issue #76: umask setting on Redhat like OSes only if authselect is not enforced

## Release 0.9.1

* Fix for issue #66
* Fix for issue #70
* Updated Github action
* PR #71: Replace legacy facts with modern facts
* PR #72: Allow for disabling of the sticky world writable and auditd cron jobs. If you have
  bigger systems where cronjobs collecting file information like for world writable files or
  auditd privileged commands might be too time consuming you can disable the cronjobs completely. 
  The default value for both jobs in `present`.

  > Please note that not running the auditd privileged commands cronjob might result in not monitoring newly installed prvileged commands.

  Keep in mind that the cronjobs are only running once a day during night hours.

Thanks to `kenyon` for the two PRs above.

## Release 0.9.0

* Puppetlabs Firewall module minimal version is now 7.0.0
* switched from `action` parameter to `jump` parameter for iptables
* switched from `provider` parameter to `protocol` parameter for iptables

  > Note that this change may affect you IPTables configuration. So please check your configuration before updating to this version.

* Updated and added some unit tests

## Release 0.8.4

* fix for issue #62

## Release 0.8.3

* added Ubuntu 22.04 support
* minor bigfixes for Redhat 9

## Release 0.8.2

* added Redhat 9 support
* added AlmaLinux 9 support
* added Rocky Linux 9 support
* fix for issue #56 "Permissions on /var/log incorrect". Added module npwalker-recursive_file_permissions for that reason.
* Updated dependencies for stdlib v9 (thanks to `canihavethisone` for the PR)

> Note that stdlib v9 is now the minimum version required

## Release 0.8.1 (not released)

* fix for issue #52, write auditd rules in a way the scanner recognices them

## Release 0.8.0

* added Debian 11 support
* renamed cronjobs in /etc/cron.d and removed `.cron` extension from filenames
* added replacement for has_key (deprecated in stdlib and was now removed)
* fix for issue #48, rsyslogd service is now notifed when rsyslogd.conf is changed.<br>Thanks to Ben Parry
* changed to fiddyspence-sysctl module

## Release 0.7.13

* omit comments during /etc/fstab reading

## Release 0.7.12

* updated dependencies
* fixed nfs fact

## Release 0.7.11

* Updated to PDK 2.7
* some linting related to PDK 2.7
* dropped support for puppet 5 and 6

Thanks to @canihavethisone:

* Updated dependencies, removed version from fixtures, added github_changelog_generator to gemfile

## Release 0.7.10

* Refactor grub_password.pp to create user.cfg in correct path on RedHat
* ensure all ntp restrict defaults to match CIS requirements
* add type to ntp servers array
* remove default rsyslog server as not required, class will fail if no remote syslog server is defined when remote syslog should be enforced
* changed `remote_log_host` parameter to type Stdlib::Host
* sshd permit root login is now configurable

## Release 0.7.9

> This release changes the default values for `ntp_statsdir` and `ntp_driftfile`. Please check your configurations if needed.

* The GRUB boot password is set to `undef` and the previous used default password was removed
* Fix facts not resolving CentOS in 3 classes
* Make NTP servers optional and raise warning if not provided, also remove hardcoded default ones
* NTP driftfile and NTP statsfile are now defined as Stdlib::Absolutepath with default values set to the same values the puppetlabs-ntp module uses
* added a fact to determine if a system is booted via efi
* fixed handling GRUB configuration for UEFI systems as the grub.cfg in the EFI directory was not updated. The grub.cfg in the EFI is only updated if there are changes to roll out.
* removed old legacy facts
* the predefined GRUB password was removed from Hiera files. If you want to enforce a GRUB bootloader password you must define this password within Hiera. Otherwise the catalog will fail with an error message pointing you to that fact.

## Release 0.7.8

* Optout for automatic reboots is now working, new parameter `auto_reboot` is available. The default value is set to `true`.
* SELinux default state is now `enforcing`
* the service for /tmp filesystem management is now enabled by default
* replaced sysctl module with `thias-sysctl`

If some of the defaults changed do not fit for your environment, just copy the parameters configuration into your control repository and set the values suitable for your environment.

## Release 0.7.7

> This release changes the hiera.yaml configuration to use OS facts to determine the files to load. Keep in mind that the OS names are written in CamelCase and therefore the filenames in the data folder will change.

* changed hiera config to use facts and renamed hiera config files to use camelcase

## Release 0.7.6

* Bugfix for /dev/shm fstab entry
* check in crypto policy exec with onlyif for idempotency
* changed default firewall to nftables for Redhat like OSes version 8
* fixed nftables rules handling
* added basic ruleset for nftables

## Release 0.7.5

> This release changed from herculesteam/augeasproviders_sysctl to fiddyspence/sysctl module. make sure to check your dependencies.

* Replaced herculesteam-augeasproviders_sysctl module by fiddyspence-sysctl module (fix for issue #28)
* removed old modules from .fixtures and metadata.json

## Release 0.7.4

Fixed issue #23: nftables resources should be within if !defined

## Release 0.7.3

* Solved issue with missing grub passwords in some paramedter files
* use a valid grub password insted of a fake string. See README.md for the default password.
* removed augeaproviders_mounttab module

## Release v0.7.2

* Added STIG benchmarks for Redhat 7 and 8
* fixed incorrect publisher for chrony
* changed augeasproviders core, pam, shellvar and grub to the new puppet modules
* removed purplehazech-syslogng dependency

## Release 0.7.1

* Added support for Redhat Linux 7 and 8
* Updated documentation
* several minor bug fixes

## Release 0.7.0

> This release contains some breaking changes to how `authselect` is configured. Please check your configuration and test before using in production environments.

Please review the following changes before updating to this version module:

* This release changes the authselect compliance rules. If you use Rocky Linux 8 or Alma Linux 8 please change your Hiera configuration. All `authselect` related stuff is consolidated into one rule file. This makes a change in your Hiera configuration necessary. The old configuration looks like this:

  ```hiera
  cis_security_hardening::rules::authselect_profile::enforce: true
  cis_security_hardening::rules::authselect_profile::custom_profile: cis
  cis_security_hardening::rules::authselect_profile::base_profile: minimal
  cis_security_hardening::rules::authselect_profile_select::enforce: true
  cis_security_hardening::rules::authselect_profile_select::custom_profile: cis
  cis_security_hardening::rules::authselect_profile_select::profile_options:
    - with-faillock
    - without-nullok
    - with-sudo
  cis_security_hardening::rules::authselect_with_faillock::enforce: true
  ```

  This should be changed into this configuration:

  ```hiera
  cis_security_hardening::rules::authselect::enforce: true
  cis_security_hardening::rules::authselect::custom_profile: cis
  cis_security_hardening::rules::authselect::base_profile: sssd
  cis_security_hardening::rules::authselect::profile_options:
    - with-faillock
    - without-nullok
    - with-sudo
  ```

* This release introduces a fact containing all available features for the slected `authselect` profile. nIf you add a profile option not available a waring message is printed and the configured option will be ignored.

* The PAM configuration rules have been changed to work with `authselect`.

## Release 0.6.2

Use a cronjob to find `suid` and `sgid` binaries to create auditd rules for these binaries.

## Release 0.6.1

Enable configuration of automatic reboots for each rule triggering such a reboot.

## Release 0.6.0

First published release indludein:

* Added Ubuntu 20.04 STIG benchmark
* Added Rocky 8 benchmark
* Added Alma Linux 8 benchmark

## Release 0.5.6

Unpublished release with the following benchmarks:

* CentOS 7
* Debian 10
* Ubuntu 18.04
* Ubuntu 20.04
* Suse Linux 12
* Suse Linux 15

## Release 0.1.0

Initial unpublished code transfered from my security_baseline module.
