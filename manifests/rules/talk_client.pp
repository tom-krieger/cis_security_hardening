# @summary 
#    Ensure talk client is not installed 
#
# The talk software makes it possible for users to send and receive messages across systems 
# through a terminal session. The talk client, which allows initialization of talk sessions, 
# is installed by default.
# 
# Rationale:
# The software presents a security risk as it uses unencrypted protocols for communication.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::talk_client':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::talk_client (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['osfamily'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    ensure_packages(['talk'], {
        ensure => $ensure,
    })
  }
}
