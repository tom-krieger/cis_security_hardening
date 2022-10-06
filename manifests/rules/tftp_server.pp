# @summary 
#    Ensure TFTP Server is not installed
#
# Trivial File Transfer Protocol (TFTP) is a simple protocol for exchanging files between two TCP/IP machines. TFTP servers allow 
# connections from a TFTP Client for sending and receiving files.
#
# Rationale:
# TFTP does not have built-in encryption, access control or authentication. This makes it very easy for an attacker to exploit 
# TFTP to gain access to files.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::tftp_server':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::tftp_server (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    ensure_packages(['tftp-server'], {
        ensure => $ensure,
    })
  }
}
