# @summary 
#    Ensure permissions on /etc/ssh/sshd_config are configured (Automated)
#
# The /etc/ssh/sshd_config file contains configuration specifications for sshd. The command below sets 
# the owner and group of the file to root.
#
# Rationale:
# The /etc/ssh/sshd_config file needs to be protected from unauthorized changes by non-privileged users.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_config_permissions':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_config_permissions (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file { $path:
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
  }
}
