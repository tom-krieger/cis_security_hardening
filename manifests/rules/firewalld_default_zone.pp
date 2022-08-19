# @summary 
#    Ensure default zone is set 
#
# A firewall zone defines the trust level for a connection, interface or source address binding. This is a one 
# to many relation, which means that a connection, interface or source can only be part of one zone, but a zone 
# can be used for many network connections, interfaces and sources.
#
# The default zone is the zone that is used for everything that is not explicitely bound/assigned to another zone.
#
# That means that if there is no zone assigned to a connection, interface or source, only the default zone is used. 
# The default zone is not always listed as being used for an interface or source as it will be used for it either way. 
# This depends on the manager of the interfaces.
#
# Connections handled by NetworkManager are listed as NetworkManager requests to add the zone binding for the 
# interface used by the connection. Also interfaces under control of the network service are listed also because the 
# service requests it.
#
# Rationale:
# Because the default zone is the zone that is used for everything that is not explicitly bound/assigned to another 
# zone, it is important for the default zone to set
#
# @param enforce
#    Enforce the rule
#
# @param default_zone
#    firewalld default zone
#
# @example
#   class { 'cis_security_hardening::rules::firewalld_default_zone':
#       enforce => true,
#       default_zone => 'private',
#   }
#
# @api private
class cis_security_hardening::rules::firewalld_default_zone (
  Cis_security_hardening::Word $default_zone,
  Boolean $enforce = false,
) {
  $fact_default_zone = fact('cis_security_hardening.firewalld.default_zone')

  if $enforce {
    if $fact_default_zone != undef and $fact_default_zone != $default_zone {
      exec { 'set firewalld default zone':
        command => "firewall-cmd --set-default-zone=${default_zone}", #lint:ignore:security_class_or_define_parameter_in_exec
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      }
    }
  }
}
