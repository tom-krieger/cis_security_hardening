# @summary
#    Notify a reboot is required
#
# Print a notifiction if a reboot is required.
#
# @example
#   include cis_security_hardening::reboot
class cis_security_hardening::reboot {
  echo { 'reboot required':
    message  => 'Automatic reboots are disabled. Please make sure to reboot as soon as possible!',
    loglevel => 'warning',
    withpath => false,
  }
}
