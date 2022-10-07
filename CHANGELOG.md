# Changelog

All notable changes to this project will be documented in this file.

## Release 0.7.3

* Solved issue with missing grub passwords in some paramedter files
* use a valid grub password insted of a fake string. See README.md for the default password.

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
