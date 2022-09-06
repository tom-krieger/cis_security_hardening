# @summary 
#    Ensure CAN is disabled
#
# The operating system must disable the controller area network (CAN) protocol. 
#
# Rationale:
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
#
# Failing to disconnect unused protocols can result in a system compromise.
#
# The Controller Area Network (CAN) is a serial communications protocol, which was initially developed for automotive and 
# is now also used in marine, industrial, and medical applications. Disabling CAN protects the system against exploitation 
# of any flaws in its implementation.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::disable_can':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_can (
  Boolean $enforce = false,
) {
  if $enforce {
    kmod::install { 'CAN':
      command => '/bin/true',
    }
    kmod::blacklist { 'CAN': }
  }
}
