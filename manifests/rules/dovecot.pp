# @summary 
#    Ensure IMAP and POP3 server is not enabled 
#
# dovecot is an open source IMAP and POP3 server for Linux based systems.
#
# Rationale:
# Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that 
# the service be disabled to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::dovecot':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::dovecot (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'ubuntu': {
        ensure_packages(['dovecot-imapd', 'dovecot-pop3d'], {
            ensure => purged,
        })
      }
      'sles': {
        ensure_packages(['dovecot'], {
            ensure => absent,
        })
      }
      default: {
        ensure_resource('service', ['dovecot'], {
            ensure => 'stopped',
            enable => false
        })
      }
    }
  }
}
