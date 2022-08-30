# @summary 
#    Ensure SSH IgnoreRhosts is enabled 
#
# The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication 
# or HostbasedAuthentication .
#
# Rationale:
# Setting this parameter forces users to enter a password when authenticating with ssh.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_ignore_rhosts':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::sshd_ignore_rhosts (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-ignore-rhosts':
      ensure => present,
      path   => $path,
      line   => 'IgnoreRhosts yes',
      match  => '^IgnoreRhosts.*',
      notify => Exec['reload-sshd'],
    }
  }
}
