# @summary
#    Handle necessary reboot
#
# Class triggered by resources requesting a system reboot
#
# @param time_until_reboot
#    Time to wait until system is rebooted if required. Time in seconds. For `reboot` the `puppetlabs-reboot` module is used. Please obey
#    the follwing comment from this module: POSIX systems (with the exception of Solaris) only support 
#    specifying the timeout as minutes. As such, the value of timeout must be a multiple of 60. Other values will be rounded up to the 
#    nearest minute and a warning will be issued.
# @param auto_reboot
#    Reboot when necessary after `time_until_reboot` is exeeded
#
# @example
#   include cis_security_hardening::reboot
class cis_security_hardening::reboot (
  Boolean $auto_reboot       = $cis_security_hardening::auto_reboot,
  Integer $time_until_reboot = $cis_security_hardening::time_until_reboot,
) {
  if $auto_reboot {
    reboot { 'after_run':
      timeout => $time_until_reboot,
      message => 'forced reboot by Puppet',
      apply   => 'finished',
    }
  }
}
