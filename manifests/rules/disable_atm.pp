# @summary
#    Ensure ATM is disabled
#
# The operating system must disable the asynchronous transfer mode (ATM) protocol. 
#
# Rationale:
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
#
# Failing to disconnect unused protocols can result in a system compromise.
#
# The Asynchronous Transfer Mode (ATM) is a protocol operating on network, data link, and physical layers, based on virtual
# circuits and virtual paths. Disabling ATM protects the system against exploitation of any laws in its implementation.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::disable_atm':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_atm (
  Boolean $enforce = false,
) {
  if $enforce {
    kmod::install { 'ATM':
      command => '/bin/true',
    }
    kmod::blacklist { 'ATM': }
  }
}
