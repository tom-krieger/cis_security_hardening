# @summary 
#    Ensure unnecessary services and ports are not accepted (Manual)
#
# Services and ports can be accepted or explicitly rejected or dropped by a zone.
#
# For every zone, you can set a default behavior that handles incoming traffic that is not further specified. 
# Such behavior is defined by setting the target of the zone. There are three options - default, ACCEPT, 
# REJECT, and DROP.
#
# * ACCEPT - you accept all incoming packets except those disabled by a specific rule.
# * REJECT - you disable all incoming packets except those that you have allowed in
#   specific rules and the source machine is informed about the rejection.
# * DROP - you disable all incoming packets except those that you have allowed in
# specific rules and no information sent to the source machine.
#
# Rationale:
# To reduce the attack surface of a system, all services and ports should be blocked unless required
#
# @param enforce
#    Enforce the rule
#
# @param expected_services
#    services to be configured in firewalld
#
# @param expected_ports
#    POrts to be configured in firewalld
#
# @example
#   class { 'cis_security_hardening::rules::firewalld_ports_services':
#       enforce => true,
#       expected_services => ['ssh'],
#       expected_ports => ['25/tcp'],
#   }
#
# @api private
class cis_security_hardening::rules::firewalld_ports_services (
  Boolean $enforce         = false,
  Array $expected_services = [],
  Array $expected_ports    = [],
) {
  if $enforce {
    $ports = fact('cis_security_hardening.firewalld.ports') == undef ? {
      true => [],
      default => fact('cis_security_hardening.firewalld.ports'),
    }

    $services = fact('cis_security_hardening.firewalld.services') == undef ? {
      true => [],
      default => fact('cis_security_hardening.firewalld.services'),
    }

    $ports.each |$port| {
      unless ($port in $expected_ports) {
        exec { "firewalld remove port ${port}":
          command => "firewall-cmd --remove-port=${port}",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
    }

    $services.each |$service| {
      unless ($service in $expected_services) {
        exec { "firewalld remove service ${service}":
          command => "firewall-cmd --remove-service=${service}",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
    }
  }
}
