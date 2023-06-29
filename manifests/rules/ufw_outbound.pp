# @summary 
#    Ensure outbound connections are configured (Not Scored)
#
# Configure the firewall rules for new outbound connections.
#
# Rationale:
# If rules are not in place for new outbound connections all packets will be dropped by the 
# default policy preventing network usage.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param firewall_rules
#    Rules for outbound connections
#
# @example
#   class cis_security_hardening::rules::ufw_outbound {
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::ufw_outbound (
  Boolean $enforce     = false,
  Hash $firewall_rules = {},
) {
  if $enforce {
    $firewall_rules.each |$title, $data| {
      if cis_security_hardening::hash_key($data, 'action') {
        unless $data['action'] =~ /\W*/ {
          fail("Illegal action: ${data['action']}")
        }
        $action = $data['action']
      } else {
        $action = ''
      }

      if cis_security_hardening::hash_key($data, 'queue') {
        unless $data['queue'] =~ /\W*/ {
          fail("Illegal queue: ${data['queue']}")
        }
        $queue = $data['queue']
      } else {
        $queue =''
      }

      if cis_security_hardening::hash_key($data, 'port') {
        unless $data['port'] =~ /^\d+$/ {
          fail("Illegal port: ${data['port']}")
        }
        $port = $data['port']
      } else {
        $port = ''
      }

      if ($data['queue'] == 'in') {
        if(cis_security_hardening::hash_key($data, 'from')) {
          unless $data['from'] =~ /^[a-zA-Z0-9\-_\.]+$/ {
            fail("Illegal from value: ${data['from']}")
          }
          $from = "from ${data['from']} "
        } else {
          $from = ''
        }

        if (cis_security_hardening::hash_key($data, 'to')) {
          unless $data['to'] =~ /^[a-zA-Z0-9\-_\.]+$/ {
            fail("Illegal to value: ${data['to']}")
          }
          $to = "to ${data['to']} "
        } else {
          $to = ''
        }

        if cis_security_hardening::hash_key($data, 'proto') {
          unless $data['proto'] in ['tcp', 'udp', 'icmp'] {
            fail("Illegal protocol: ${data['proto']}")
          }
          $proto = $data['proto']
        } else {
          $proto = ''
        }

        if($from == '') and ($to == '') {
          $cmd = "ufw allow ${port}/${proto}"
        } else {
          $cmd = "ufw ${action} proto ${proto} ${from}${to}port ${port}"
        }
        $check = "test -z \"$(ufw status verbose | grep -E -i '^${port}/${proto}.*ALLOW ${queue}')\""
      } elsif ($data['queue'] == 'out') {
        $cmd = "ufw ${action} ${queue} to ${data['to']} port ${port}"
        $check = "test -z \"$(ufw status verbose | grep -E -i '^${port}.*ALLOW ${queue}')\""
      } else {
        fail("unknow ufw queue ${data['queue']}")
      }

      exec { $title:
        command => $cmd,
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        onlyif  => $check,
      }
    }
  }
}
