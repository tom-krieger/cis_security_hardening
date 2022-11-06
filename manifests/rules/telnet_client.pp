# @summary 
#    Ensure telnet client is not installed 
#
# The telnet package contains the telnet client, which allows users to start connections to other 
# systems via the telnet protocol.
# 
# Rationale:
# The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium 
# could allow an unauthorized user to steal credentials. The ssh package provides an encrypted 
# session and stronger security and is included in most Linux distributions.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::telnet_client':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::telnet_client (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['family'].downcase() {
      'suse': {
        ensure_packages(['telnet'], {
            ensure => 'absent',
        })
      }
      default: {
        ensure_packages(['telnet'], {
            ensure => 'purged',
        })
      }
    }
  }
}
