# @summary#
#    Ensure the operating system disables the ability to load the firewire-core kernel module
#
# The operating system must disable IEEE 1394 (FireWire) Support. 
#
# Rationale:
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
#
# The IEEE 1394 (FireWire) is a serial bus standard for high-speed real-time communication. Disabling FireWire protects 
# the system against exploitation of any flaws in its implementation.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::firewire_core':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::firewire_core (
  Boolean $enforce = false,
) {
  if $enforce {
    kmod::install { 'firewire-core':
      command => '/bin/true',
    }
  }
}
