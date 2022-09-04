# @summary 
#    Ensure SSH is installed and active
#
# The operating system must use SSH to protect the confidentiality and integrity of transmitted information.
#
# Rationale:
# Without protection of the transmitted information, confidentiality and integrity may be compromised because 
# unprotected communications can be intercepted and either read or altered.
#
# This requirement applies to both internal and external networks and all types of information system 
# components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, 
# printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of 
# a controlled boundary are exposed to the possibility of interception and modification.
#
# Protecting the confidentiality and integrity of organizational information can be accomplished by physical 
# means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic 
# techniques). If physical means of protection are employed, then logical means (cryptography) do not have to 
# be employed, and vice versa.
#
# Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000425-GPOS-00189, SRG-OS-000426- GPOS-00190
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_install':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_install (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['ssh'], {
        ensure => present,
    })

    ensure_resource('service', 'sshd', {
        enable => true,
        ensure => running,
    })
  }
}
