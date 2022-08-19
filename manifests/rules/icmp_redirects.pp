# @summary 
#    Ensure ICMP redirects are not accepted 
#
# ICMP redirect messages are packets that convey routing information and tell your host 
# (acting as a router) to send packets via an alternate path. It is a way of allowing an 
# outside routing device to update your system routing tables. By setting net.ipv4.conf.all.accept_redirects 
# to 0, the system will not accept any ICMP redirect messages, and therefore, won't allow outsiders to update 
# the system's routing tables.
#
# Rationale:
# Attackers could use bogus ICMP redirect messages to maliciously alter the system routing tables and get 
# them to send packets to incorrect networks and allow your system packets to be captured.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::icmp_redirects':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::icmp_redirects (
  Boolean $enforce = false,
) {
  if $enforce {
    Sysctl {
      'net.ipv4.conf.all.accept_redirects':
        value => 0,
    }
    Sysctl {
      'net.ipv4.conf.default.accept_redirects':
        value => 0,
    }

    if fact('network6') != undef {
      Sysctl {
        'net.ipv6.conf.all.accept_redirects':
          value => 0,
      }
      Sysctl {
        'net.ipv6.conf.default.accept_redirects':
          value => 0,
      }
    }
  }
}
