# @summary 
#    Reboot
#
# Class triggered by resources requesting a system reboot
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
