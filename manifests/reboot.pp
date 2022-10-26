# @summary 
#    Reboot
#
# Class triggered by resources requesting a system reboot
#
# @example
#   include cis_security_hardening::reboot
class cis_security_hardening::reboot {
  if $cis_security_hardening::auto_reboot {
    reboot { 'after_run':
      timeout => $cis_security_hardening::time_until_reboot,
      message => 'forced reboot by Puppet',
      apply   => 'finished',
    }
  } else {
    echo { 'reboot required':
      message  => 'A system reboot has been triggered but overridden with auto_reboot => false
         Please ensure to reboot your system for changes to take effect.',
      loglevel => 'warning',
      withpath => false,
    }
  }
}
