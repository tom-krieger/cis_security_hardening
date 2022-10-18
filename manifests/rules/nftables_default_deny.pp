# @summary 
#     Ensure default deny firewall policy 
#
# Base chain policy is the default verdict that will be applied to packets reaching the end of the chain.
#
# Rationale:
# There are two policies: accept (Default) and drop. If the policy is set to accept, the firewall will 
# accept any packet that is not configured to be denied and the packet will continue transversing the 
# network stack.
# It is easier to white list acceptable usage than to black list unacceptable usage.
#
# @param enforce
#    Enforce the rule
#
# @param default_policy_input
#    Default input policy
#
# @param default_policy_forward
#    Default forward policy
#
# @param default_policy_output
#    Default output policy
#
# @param table
#    nftable table to add rules
#
# @param additional_rules
#    additinals rules to add to te policy. Add an array with rules to teh hash. Hash key is the chain 
#    to add the rules.
#
# @example
#   class { 'cis_security_hardening::rules::nftables_default_deny':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::nftables_default_deny (
  Boolean $enforce                                         = false,
  Enum['accept', 'reject', 'drop'] $default_policy_input   = 'drop',
  Enum['accept', 'reject', 'drop'] $default_policy_output  = 'drop',
  Enum['accept', 'reject', 'drop'] $default_policy_forward = 'drop',
  Cis_security_hardening::Nftables_address_families $table = 'inet',
  Hash $additional_rules                                   = {},
) {
  if $enforce {
    exec { 'set input default policy':
      command => "nft chain ${table} filter input { policy ${default_policy_input} \\; }", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list chains ${table} | grep 'hook input.*policy ${default_policy_input};')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'set forward default policy':
      command => "nft chain ${table} filter forward { policy ${default_policy_forward} \\; }", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list chains ${table} | grep 'hook forward.*policy ${default_policy_forward};')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'set output default policy':
      command => "nft chain ${table} filter output { policy ${default_policy_output} \\; }", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list chains ${table} | grep 'hook output.*policy ${default_policy_output};')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    $additional_rules.each |$chain, $rules| {
      $rules.each |$rule| {
        unless $chain =~ /^[0-9a-zA-Z\-_\.]+$/ {
          fail("Illegal chain: ${chain}")
        }
        unless $rule =~ /^[0-9a-zA-Z\-_\.\s]+$/ {
          fail("Illegal rule: ${rule}")
        }
        $cmd = "nft add rule ${table} filter ${chain} ${rule}"

        exec { "adding rule ${rule}":
          command => $cmd,
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          onlyif  => "test -z \"$(nft list chain ${table} filter ${chain})\"",
          # onlyif  => "test -z \"$(nft list ruleset ${table} | grep '${rule}')\"",
          notify  => Exec['dump nftables ruleset'],
        }
      }
    }
  }
}
