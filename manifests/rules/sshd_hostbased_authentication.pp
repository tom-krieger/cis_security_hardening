# @summary 
#    Ensure SSH HostbasedAuthentication is disabled 
#
# The HostbasedAuthentication parameter specifies if authentication is allowed through trusted hosts via the user 
# of .rhosts , or /etc/hosts.equiv , along with successful public key client host authentication. This option only 
# applies to SSH Protocol Version 2.
#
# Rationale:
# Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf , disabling the ability to 
# use .rhosts files in SSH provides an additional layer of protection .
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_hostbased_authentication':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::sshd_hostbased_authentication (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-hostbased-auth':
      ensure => present,
      path   => $path,
      line   => 'HostbasedAuthentication no',
      match  => '^HostbasedAuthentication.*',
      notify => Exec['reload-sshd'],
    }
  }
}
