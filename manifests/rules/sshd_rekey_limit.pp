# @summary 
#    Ensure the SSH server is configured to force frequent session key renegotiation
#
# The operating system must force a frequent session key renegotiation for SSH connections to the server.
#
# Rationale:
# Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected 
# communications can be intercepted and either read or altered.
#
# This requirement applies to both internal and external networks and all types of information system components from which 
# information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile 
# machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of 
# interception and modification.
#
# Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing 
# physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are 
# employed, then logical means (cryptography) do not have to be employed, and vice versa.
#
# Session key regeneration limits the chances of a session key becoming compromised. Satisfies: SRG-OS-000033-GPOS-00014, 
# SRG-OS-000420-GPOS-00186, SRG-OS-000424- GPOS-00188
#
# @param enforce
#    Enforce the rule.
# @param limit
#    Reke limit setting.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_rekey_limit':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_rekey_limit (
  Boolean $enforce = false,
  String $limit    = '1G 1h',
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-rekey-limit':
      ensure             => present,
      path               => $path,
      line               => "RekeyLimit ${limit}",
      match              => '^RekeyLimit.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}
