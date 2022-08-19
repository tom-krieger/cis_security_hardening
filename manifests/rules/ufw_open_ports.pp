# @summary 
#    Ensure firewall rules exist for all open ports 
#
# Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.
#
# Rationale:
# Without a firewall rule configured for open ports default firewall policy will drop all packets to these ports.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param firewall_rules
#    Rules for inbound connections
#
# @example
#   class cis_security_hardening::rules::debian::sec_ufw_open_ports {
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::ufw_open_ports (
  Boolean $enforce     = false,
  Hash $firewall_rules = {},
) {
  if $enforce {
    $firewall_rules.each |$title, $data| {
      if has_key($data, 'action') {
        unless $data['action'] =~ /\W*/ {
          fail("Illegal action: ${data['action']}")
        }
        $action = $data['action']
      } else {
        $action = ''
      }

      if has_key($data, 'queue') {
        unless $data['queue'] =~ /\W*/ {
          fail("Illegal queue: ${data['queue']}")
        }
        $queue = $data['queue']
      } else {
        $queue =''
      }

      if has_key($data, 'port') {
        unless $data['port'] =~ /^\d+$/ {
          fail("Illegal port: ${data['port']}")
        }
        $port = $data['port']
      } else {
        $port = ''
      }

      if ($data['queue'] == 'in') {
        if(has_key($data, 'from')) {
          unless $data['from'] =~ /^[a-zA-Z0-9\-_\.]+$/ {
            fail("Illegal from value: ${data['from']}")
          }
          $from = "from ${data['from']} "
        } else {
          $from = ''
        }

        if (has_key($data, 'to')) {
          unless $data['to'] =~ /^[a-zA-Z0-9\-_\.]+$/ {
            fail("Illegal to value: ${data['to']}")
          }
          $to = "to ${data['to']} "
        } else {
          $to = ''
        }

        if has_key($data, 'proto') {
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
        fail("unknow ufw queue ${queue}")
      }

      exec { $title:
        command => $cmd,
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        onlyif  => $check,
      }
    }
  }
}
