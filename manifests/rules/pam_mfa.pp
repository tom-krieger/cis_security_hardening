# @summary 
#    Ensure smart card logins for multifactor authentication for local and network access
#
# The operating system must implement smart card logins for multifactor authentication for local 
# and network access to privileged and non-privileged accounts.
#
# Rationale:
# Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.
#
# Multifactor authentication requires using two or more factors to achieve authentication. Factors include:
# 1. something a user knows (e.g., password/PIN);
# 2. something a user has (e.g., cryptographic identification device, token); and
# 3. something a user is (e.g., biometric).
#
# A privileged account is defined as an information system account with authorizations of a privileged user.
#
# Network access is defined as access to an information system by a user (or a process acting on behalf of a 
# user) communicating through a network (e.g., local area network, wide area network, or the internet).
#
# The DoD CAC with DoD-approved PKI is an example of multifactor authentication.
#
# Satisfies: SRG-OS-000105-GPOS-00052, SRG-OS-000106-GPOS-00053, SRG-OS-000107- GPOS-00054, SRG-OS-000108-GPOS-00055
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::pam_mfa':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::pam_mfa (
  Boolean $enforce = false
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }

    file_line { 'sshd-mfa-login':
      ensure => present,
      path   => $path,
      line   => 'PubkeyAuthentication yes',
      match  => '^PubkeyAuthentication.*',
      notify => Exec['reload-sshd'],
    }

    Pam { 'pam-common-mfa':
      ensure           => present,
      service          => 'common-auth',
      type             => 'auth',
      control          => '[success=2 default=ignore]',
      control_is_param => true,
      module           => 'pam_pkcs11.so',
    }
  }
}
