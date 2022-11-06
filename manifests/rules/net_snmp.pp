# @summary 
#    Ensure net-snmp is not installed 
#
# Simple Network Management Protocol (SNMP) is a widely used protocol for monitoring the health and welfare 
# of network equipment, computer equipment and devices like UPSs.
#
# Net-SNMP is a suite of applications used to implement SNMPv1 (RFC 1157), SNMPv2 (RFCs 1901-1908), and SNMPv3 
# (RFCs 3411-3418) using both IPv4 and IPv6.
#
# Support for SNMPv2 classic (a.k.a. "SNMPv2 historic" - RFCs 1441-1452) was dropped with the 4.0 release of 
# the UCD-snmp package.
#
# The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management 
# system, execute the commands or collect the information and then send results back to the requesting system.
#
# Rationale:
# The SNMP server can communicate using SNMPv1, which transmits data in the clear and does not require authentication 
# to execute commands. SNMPv3 replaces the simple/clear text password sharing used in SNMPv2 with more securely encoded 
# parameters. If the the SNMP service is not required, the net-snmp package should be removed to reduce the attack 
# surface of the system.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::net_snmp':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::net_snmp (
  Boolean $enforce = false,
) {
  if $enforce {
    if $facts['os']['name'].downcase() == 'ubuntu' {
      $pkg = 'snmpd'
    } else {
      $pkg = 'net-snmp'
    }

    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    ensure_packages($pkg, {
        ensure => $ensure,
    })
  }
}
