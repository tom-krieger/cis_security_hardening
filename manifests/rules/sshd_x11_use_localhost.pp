# @summary 
#    Ensure X11UseLocalhost is enabled
#
# The operating system SSH daemon must prevent remote hosts from connecting to the proxy display.
#
# Rationale:
# When X11 forwarding is enabled, there may be additional exposure to the server and client displays 
# if the sshd proxy display is configured to listen on the wildcard address. By default, sshd binds 
# the forwarding server to the loopback address and sets the hostname part of the DISPLAY environment 
# variable to localhost. This prevents remote hosts from connecting to the proxy display.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_x11_use_localhost':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_x11_use_localhost (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true  => '/usr/etc/ssh/sshd_config',
      false => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-x11-use-localhost':
      ensure => present,
      path   => $path,
      line   => 'X11UseLocalhost yes',
      match  => '^#?X11UseLocalhost.*',
      notify => Exec['reload-sshd'],
    }
  }
}
