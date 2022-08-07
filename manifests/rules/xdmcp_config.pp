# @summary
#    Ensure XDCMP is not enabled (Automated)
#
# X Display Manager Control Protocol (XDMCP) is designed to provide authenticated access to display 
# management services for remote displays
#
# Rationale:
# XDMCP is inherently insecure.
#   * XDMCP is not a ciphered protocol. This may allow an attacker to capture keystrokes entered by a user
#   * XDMCP is vulnerable to man-in-the-middle attacks. This may allow an attacker to steal the credentials 
#     of legitimate users by impersonating the XDMCP server.
#
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::xdmcp_config':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::xdmcp_config (
  Boolean $enforce = false,
) {
  $xdcmp = fact('cis_security_hardening.xdcmp')
  if  $enforce and $xdcmp != undef and $xdcmp {
    file_line { 'remove enable':
      ensure            => absent,
      path              => '/etc/gdm3/custom.conf',
      match             => 'Enable=true',
      match_for_absence => true,
    }
  }
}
