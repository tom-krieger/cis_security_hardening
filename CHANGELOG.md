# Changelog

All notable changes to this project will be documented in this file.

## Release 0.7.9

> This release changes the default values for `ntp_statsdir` and `ntp_driftfile`. Please check your configurations if needed.

* The GRUB boot password is set to `undef` and the previous used default password was removed
* Fix facts not resolving CentOS in 3 classes
* Make NTP servers optional and raise warning if not provided, also remove hardcoded default ones
* NTP driftfile and NTP statsfile are now defined as Stdlib::Absolutepath with default values set to the same values the puppetlabs-ntp module uses
* added a fact to determine if a system is booted via efi
* fixed handling GRUB configuration for UEFI systems as the grub.cfg in the EFI directory was not updated. The grub.cfg in the EFI is only updated if there are changes to roll out.

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
