# @summary
#    Ensure the operating system has the packages required for encrypting offloaded audit logs
#
# must have the packages required for encrypting offloaded audit logs installed.
#
# Rationale:
# Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
#
# Off-loading is a common process in information systems with limited audit storage capacity.
#
# The operating system's installation media provides "rsyslogd". "rsyslogd" is a system utility providing support for 
# message logging. Support for both internet and UNIX domain sockets enables this utility to support both local and 
# remote logging. Couple this utility with "rsyslog-gnutls" (which is a secure communications library implementing the 
# SSL, TLS and DTLS protocols), and you have a method to securely encrypt and off-load auditing.
#
# Rsyslog provides three ways to forward message: the traditional UDP transport, which is extremely lossy but standard; 
# the plain TCP based transport, which loses messages only during certain situations but is widely available; and the RELP 
# transport, which does not lose messages but is currently available only as part of the rsyslogd 3.15.0 and above.
#
# Examples of each configuration: UDP . @remotesystemname TCP . @@remotesystemname RELP . :omrelp:remotesystemname:2514 
# Note that a port number was given as there is no standard port for RELP.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_rsyslog_gnutls':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_rsyslog_gnutls (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['rsyslog-gnutls'], {
        ensure => installed,
    })
  }
}
