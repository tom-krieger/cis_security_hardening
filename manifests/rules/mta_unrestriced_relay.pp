# @summary
#    Ensure unrestricted mail relaying is prevented
#
# The operating system must be configured to prevent unrestricted mail relaying.
#
# Rationale:
# If unrestricted mail relaying is permitted, unauthorized senders could use this host as a 
# mail relay for the purpose of sending spam or other unauthorized activity.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::mta_unrestriced_relay':
#     enforce => true,
#   }

# @api private
class cis_security_hardening::rules::mta_unrestriced_relay (
  Boolean $enforce = false,
) {
  if $enforce {
    exec { 'restrict mail relay':
      command => 'postconf -e \'smtpd_client_restrictions = permit_mynetworks,reject\'',
      path    => ['/bin','/usr/bin','/sbin','/usr/sbin'],
      onlyif  => 'test -z "$(postconf -n smtpd_client_restrictions | grep \'permit_mynetworks, reject\')"',
    }
  }
}
