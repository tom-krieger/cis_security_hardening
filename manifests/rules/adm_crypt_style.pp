# @summary
#    nsure user and group account administration utilities are configured to store only encrypted representations of passwords
#
# The operating system must be configured so that user and group account administration utilities are configured to store only 
# encrypted representations of passwords.
#
# Rationale:
# Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are 
# not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm 
# are no more protected than if they are kept in plain text.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::adm_crypt_style':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::adm_crypt_style (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'crypt_style':
      ensure             => present,
      path               => '/etc/libuser.conf',
      match              => 'crypt_style =',
      line               => 'crypt_style = sha512',
      append_on_no_match => true,
    }
  }
}
