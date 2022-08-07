# @summary
#    Ensure telnet-server is not installed (Automated)
#
# The telnet-server package contains the telnet daemon, which accepts connections from users from 
# other systems via the telnet protocol.
#
# Rationale:
# The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium 
# could allow a user with access to sniff network traffic the ability to steal credentials. The ssh 
# package provides an encrypted session and stronger security.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::telnet_server':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::telnet_server (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['osfamily'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    unless $facts['operatingsystem'].downcase() == 'sles' {
      ensure_resource('service', ['telnet'], {
          ensure => stopped,
          enable => false,
      })
    }
    ensure_packages(['telnet-server'], {
        ensure => $ensure,
    })
  }
}
