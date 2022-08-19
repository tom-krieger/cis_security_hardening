# @summary
#    Ensure ENCRYPT_METHOD is SHA512
#
# The operating system must encrypt all stored passwords with a FIPS 140-2 approved cryptographic 
# hashing algorithm.
#
# Rationale:
# Passwords need to be protected at all times, and encryption is the standard method for protecting 
# passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily 
# compromised.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::passwd_sh512':
#     enforce => true
#   }
#
# @api private
class cis_security_hardening::rules::passwd_sha512 (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true  => '/usr/etc/login.defs',
      false => '/etc/login.defs',
    }
    file_line { 'password sha512':
      ensure => present,
      path   => $path,
      line   => 'ENCRYPT_METHOD SHA512',
      match  => '^#?ENCRYPT_METHOD',
    }
  }
}
