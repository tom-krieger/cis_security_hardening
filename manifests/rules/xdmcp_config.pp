# @summary
#    Ensure XDCMP is not enabled 
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
# @api public
class cis_security_hardening::rules::xdmcp_config (
  Boolean $enforce = false,
) {
  $xdcmp = fact('cis_security_hardening.xdcmp')

  if  $enforce and $xdcmp != undef and $xdcmp {
    $file = $facts['os']['name'].downcase() ? {
      'rocky'     => '/etc/gdm/custom.conf',
      'almalinux' => '/etc/gdm/custom.conf',
      'redhat'    => '/etc/gdm/custom.conf',
      'centos'    => '/etc/gdm/custom.conf',
      default     => '/etc/gdm3/custom.conf',
    }

    file_line { 'remove enable':
      ensure            => absent,
      path              => $file,
      match             => 'Enable=true',
      match_for_absence => true,
    }
  }
}
