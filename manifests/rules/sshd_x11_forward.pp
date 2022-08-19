# @summary 
#    Ensure SSH X11 forwarding is disabled 
#
# The X11Forwarding parameter provides the ability to tunnel X11 traffic through the connection to enable remote 
# graphic connections.
#
# Rationale:
# Disable X11 forwarding unless there is an operational requirement to use X11 applications directly. There is a small 
# risk that the remote X11 servers of users who are logged in via SSH with X11 forwarding could be compromised by other 
# users on the X11 server. Note that even if X11 forwarding is disabled, users can always install their own forwarders.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_x11_forward':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_x11_forward (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true  => '/usr/etc/ssh/sshd_config',
      false => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-x11-forward':
      ensure => present,
      path   => $path,
      line   => 'X11Forwarding no',
      match  => '^X11Forwarding.*',
      notify => Exec['reload-sshd'],
    }
  }
}
