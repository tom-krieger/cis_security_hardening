# @summary 
#    Ensure TFTP client is not installed
#
# Trivial File Transfer Protocol (TFTP) is a simple protocol for ex changing files between two TCP/IP 
# machines. TFTP servers allow connections from a TFTP Client for sending and receiving files.
#
# Rationale:
# TFTP does not have built-in encryption, access control or authentication. This makes it very easy for an attacker to exploit 
# TFTP to gain access to files.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::tftp_client':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::tftp_client (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['tftp'], {
        ensure => absent,
    })
  }
}
