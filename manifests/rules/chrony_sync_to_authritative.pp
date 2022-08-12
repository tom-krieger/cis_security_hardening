# @summary
#    Ensure system clocks are synchronize to the authoritative time source when the time difference is greater than one second
#
# The operating system must synchronize internal information system clocks to the authoritative time source when the time difference 
# is greater than one second.
#
# Rationale:
# Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct 
# time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events.
#
# Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system 
# clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems 
# (e.g., financial, legal, or mission-critical systems).
#
# Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, 
# teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in SRG-OS-000355 because 
# a comparison must be done in order to determine the time difference.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::chrony_sync_to_authritative':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::chrony_sync_to_authritative (
  Boolean $enforce = false,
) {
  # $chrony = lookup('cis_security_hardening::rules::chrony::enforce')
  if $enforce {
    file_line { 'sync chrony':
      ensure             => present,
      path               => '/etc/chrony/chrony.conf',
      match              => '^makestep',
      line               => 'makestep 1 -1',
      append_on_no_match => true,
    }
  }
}
