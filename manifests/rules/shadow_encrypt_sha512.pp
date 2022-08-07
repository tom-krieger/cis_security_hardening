# @summary 
#    Ensure password hashing algorithm is SHA-512 (Automated)
#
# Login passwords are hashed and stored in the /etc/shadow file.
#
# Note: These changes only apply to accounts configured on the local system.
#
# Rationale:
# The SHA-512 algorithm provides much stronger hashing than MD5, thus providing additional protection to the system 
# by increasing the level of effort for an attacker to successfully determine passwords.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::shadow_encrypt_sha512':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::shadow_encrypt_sha512 (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true  => '/usr/etc/login.defs',
      false => '/etc/login.defs',
    }
    file_line { 'login.defs':
      path               => $path,
      line               => 'ENCRYPT_METHOD sha512',
      match              => '^\s*ENCRYPT_METHOD',
      append_on_no_match => true,
      multiple           => true,
    }
  }
}
