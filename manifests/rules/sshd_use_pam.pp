# @summary 
#    Ensure SSH PAM is enabled 
#
# UsePAM Enables the Pluggable Authentication Module interface. If set to “yes” this will 
# enable PAM authentication using ChallengeResponseAuthentication and PasswordAuthentication 
# in addition to PAM account and session module processing for all authentication types.
#
# Rationale:
# When usePAM is set to yes, PAM runs through account and session types properly. This is 
# important if you want to restrict access to services based off of IP, time or other factors 
# of the account. Additionally, you can make sure users inherit certain environment variables 
# on login or disallow access to the server
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_use_pam':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_use_pam (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-use-pam':
      ensure             => present,
      path               => $path,
      line               => 'UsePAM yes',
      match              => '^#?UsePAM.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}
