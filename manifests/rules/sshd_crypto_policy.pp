# @summary 
#    Ensure system-wide crypto policy is not over-ridden 
#
# System-wide Crypto policy can be over-ridden or opted out of for openSSH.
#
# Rationale:
# Over-riding or opting out of the system-wide crypto policy could allow for the use of 
# less secure Ciphers, MACs, KexAlgoritms and GSSAPIKexAlgorithsm.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @example
#   class cis_security_hardening::rules::sshd_crypto_polic {
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_crypto_policy (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-crypto-policy':
      ensure            => absent,
      path              => $path,
      match             => '^\s*CRYPTO_POLICY\s*=.*',
      match_for_absence => true,
      notify            => Exec['reload-sshd'],
    }
  }
}
