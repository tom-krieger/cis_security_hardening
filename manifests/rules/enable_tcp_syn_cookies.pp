# @summary 
#    Ensure TCP SYN Cookies is enabled 
#
# When tcp_syncookies is set, the kernel will handle TCP SYN packets normally until the half-open 
# connection queue is full, at which time, the SYN cookie functionality kicks in. SYN cookies work 
# by not using the SYN queue at all. Instead, the kernel simply replies to the SYN with a SYN|ACK, 
# but will include a specially crafted TCP sequence number that encodes the source and destination 
# IP address and port number and the time the packet was sent. A legitimate connection would send 
# the ACK packet of the three way handshake with the specially crafted sequence number. This allows 
# the system to verify that it has received a valid response to a SYN cookie and allow the connection, 
# even though there is no corresponding SYN in the queue.
#
# Rationale:
# Attackers use SYN flood attacks to perform a denial of service attacked on a system by sending many 
# SYN packets without completing the three way handshake. This will quickly use up slots in the kernel's 
# half-open connection queue and prevent legitimate connections from succeeding. SYN cookies allow the 
# system to keep accepting valid connections, even if under a denial of service attack.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class cis_security_hardening::rules::enable_tcp_syn_cookies {
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::enable_tcp_syn_cookies (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'net.ipv4.tcp_syncookies':
        ensure    => present,
        permanent => 'yes',
        value     => 1,
    }
  }
}
