# @summary 
#    Ensure default deny firewall policy 
#
# A default deny policy on connections ensures that any unconfigured network usage will be rejected.
#
# Rationale:
# With a default accept policy the firewall will accept any packet that is not configured to be denied. 
# It is easier to white list acceptable usage than to black list unacceptable usage.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param default_incoming
#    Default policy for incoming traffic
#
# @param default_outgoing
#    Default policy for outgoing traffic
#
# @param default_routed
#    Default policy for routed traffic
#
# @example
#   class cis_security_hardening::rules::ufw_default_deny {
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::ufw_default_deny (
  Boolean $enforce                        = false,
  Enum['allow', 'deny'] $default_incoming = 'allow',
  Enum['allow', 'deny'] $default_outgoing = 'allow',
  Enum['allow', 'deny'] $default_routed   = 'allow',
) {
  if $enforce {
    exec { "default incoming policy ${default_incoming}":
      command => "ufw default ${default_incoming} incoming", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(ufw status verbose | grep '${default_incoming} (incoming)')\"",
    }

    exec { "default outgoing policy ${default_outgoing}":
      command => "ufw default ${default_outgoing} outgoing", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(ufw status verbose | grep '${default_outgoing} (outgoing)')\"",
    }

    # exec only if default policy for routed traffic is not the desired state or id not completely disabled
    exec { "default routed policy ${default_routed}":
      command => "ufw default ${default_routed} routed", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(ufw status verbose | grep -e '${default_routed} (routed)' -e 'disabled (routed)')\"",
    }
  }
}
