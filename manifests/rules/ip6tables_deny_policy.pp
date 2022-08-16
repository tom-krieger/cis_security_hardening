# @summary 
#     Ensure default deny firewall policy (Automated)
#
# A default deny all policy on connections ensures that any unconfigured network usage will be rejected.
#
# Rationale:
# With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier 
# to white list acceptable usage than to black list unacceptable usage.
#
# @param enforce
#    Enforce the rule
#
# @param input_policy
#    The default policy for the input chain
#
# @param output_policy
#    The default policy for the output chain
#
# @param forward_policy
# The default policy for the forward chain
#
# @example
#   class { 'cis_security_hardening::rules::ip6tables_deny_policy':
#       enforce => true,
#       input_policy => 'drop',
#       output_policy => 'accept',
#       forward_policy => 'drop',
#   }
#
# @example
#   include cis_security_hardening::rules::ip6tables_deny_policy
#
# @api private
class cis_security_hardening::rules::ip6tables_deny_policy (
  Boolean $enforce                       = false,
  Enum['drop', 'accept'] $input_policy   = 'drop',
  Enum['drop', 'accept'] $output_policy  = 'accept',
  Enum['drop', 'accept'] $forward_policy = 'drop',
) {
  if  $enforce and fact('network6') != undef {
    firewallchain { 'OUTPUT:filter:IPv6':
      ensure => present,
      policy => $output_policy,
    }

    firewallchain { 'FORWARD:filter:IPv6':
      ensure => present,
      policy => $forward_policy,
    }

    firewallchain { 'INPUT:filter:IPv6':
      ensure => present,
      policy => $input_policy,
    }
  }
}
