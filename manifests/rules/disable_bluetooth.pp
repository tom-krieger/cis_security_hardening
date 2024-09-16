# @summary
#    Ensure Bluetooth is disabled
#
# Bluetooth must be disabled. 
#
# Rationale:
# Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because 
# unprotected communications can be intercepted and either read, altered, or used to compromise the operating system.
#
# This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with 
# RHEL 8 operating systems. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and Near 
# Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals 
# must meet DoD requirements for wireless data transmission and be approved for use by the Authorizing Official (AO). Even 
# though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be 
# protected, modification of communications with these wireless peripherals may be used to compromise the operating system. 
# Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception 
# and modification.
#
# Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical 
# means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic 
# techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, 
# and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.
#
# @param enforce
#    Enforcve the rule.
#
# @example
#   class { 'cis_security_hardening::rules::disable_bluetooth':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_bluetooth (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'ubuntu': {
        if $facts['os']['release']['major'] >= '20' {
          service { 'bluetooth.service':
            ensure => 'stopped',
            enable => false,
          }
        } else {
          kmod::install { 'bluetooth':
            command => '/bin/true',
          }
        }
      }
      'debian': {
        if $facts['os']['release']['major'] >= '12' {
          service { 'bluetooth.service':
            ensure => 'stopped',
            enable => false,
          }
        } else {
          kmod::install { 'bluetooth':
            command => '/bin/true',
          }
        }
      }
      'centos': {
        service { 'bluetooth.service':
          ensure => 'stopped',
          enable => false,
        }
        ensure_packages(['bluez'], {
            ensure => absent,
        })
      }
      default: {
        kmod::install { 'bluetooth':
          command => '/bin/true',
        }
      }
    }
  }
}
