# @summary
#    Disable USB Storage
#
# USB storage provides a means to transfer and store files insuring persistence and availability of the files
# independent of network connection status. Its popularity and utility has led to USB-based malware being a
# simple and common means for network infiltration and a first step to establishing a persistent threat within
# a networked environment.
#
# Rationale:
# Restricting USB access on the system will decrease the physical attack surface for a device and diminish the
# possible vectors to introduce malware.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::disable_usb_storage':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_usb_storage (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'debian': {
        if $facts['os']['release']['major'] > '12'{
          $command = '/bin/false'
          kmod::blacklist { 'usb-storage': }
        } else {
          $command = '/bin/true'
        }
      }
      'redhat': {
        if $facts['os']['release']['major'] > '8' {
          $command = '/bin/false'
          kmod::blacklist { 'usb-storage': }
        } else {
          $command = '/bin/true'
        }
      }
      'ubuntu': {
        if $facts['os']['name'].downcase() == 'ubuntu' and $facts['os']['release']['major'] >= '20' {
          $command = '/bin/false'
          kmod::blacklist { 'usb-storage': }
        } else {
          $command = '/bin/true'
        }
      }
      default: {
        $command = '/bin/true'
      }
    }

    kmod::install { 'usb-storage':
      command => $command,
    }
  }
}
