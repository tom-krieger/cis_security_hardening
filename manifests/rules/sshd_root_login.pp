# @summary 
#    Ensure SSH root login is disabled 
#
# The PermitRootLogin parameter specifies if the root user can log in using ssh(1). The default is no.
#
# Rationale:
# Disallowing root logins over SSH requires system admins to authenticate using their own individual account, 
# then escalating to root via sudo or su . This in turn limits opportunity for non-repudiation and provides 
# a clear audit trail in the event of a security incident
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_root_login':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_root_login (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-root-login':
      ensure => present,
      path   => $path,
      line   => 'PermitRootLogin no',
      match  => '^PermitRootLogin.*',
      notify => Exec['reload-sshd'],
    }
  }
}
