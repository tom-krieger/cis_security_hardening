# @summary 
#    Ensure DCCP is disabled 
#
# The Datagram Congestion Control Protocol (DCCP) is a transport layer protocol that supports 
# streaming media and telephony. DCCP provides a way to gain access to congestion control, without 
# having to do it at the application layer, but does not provide in- sequence delivery.
#
# Rationale:
# If the protocol is not required, it is recommended that the drivers not be installed to reduce the 
# potential attack surface.
#
# @param enforce
#    Enforce the rule
#
#
# @example
#   class { 'cis_security_hardening::rules::disable_dccp':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::disable_dccp (
  Boolean $enforce = false,
) {
  if $enforce {
    kmod::install { 'dccp':
      command => '/bin/true',
    }
  }
}
