# @summary 
#    Ensure SSH warning banner is configured 
#
# The Banner parameter specifies a file whose contents must be sent to the remote user before authentication is permitted. 
# By default, no banner is displayed.
#
# Rationale:
# Banners are used to warn connecting users of the particular site's policy regarding connection. Presenting a warning 
# message prior to the normal user login may assist the prosecution of trespassers on the computer system.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_banner':
#       enforce => true,
#   }

#
# @api private
class cis_security_hardening::rules::sshd_banner (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-banner':
      ensure => present,
      path   => $path,
      line   => 'Banner /etc/issue.net',
      match  => '^#?Banner.*',
      notify => Exec['reload-sshd'],
    }
  }
}
