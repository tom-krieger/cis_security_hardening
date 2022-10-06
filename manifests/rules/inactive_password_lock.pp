# @summary
#    Ensure inactive password lock is 0 days
#
# The operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires.
#
# Rationale:
# Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and 
# potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access 
# to their user account has been obtained.
#
# Operating systems need to track periods of inactivity and disable application identifiers after zero days of inactivity.
#
# @param enforce
#    Enforce the rule.
# @param inactive_days
#    Inactivr days.
#
# @example
#   class { 'cis_security_hardening::rules::inactive_password_lock':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::inactive_password_lock (
  Boolean $enforce       = false,
  Integer $inactive_days = 30,
) {
  if $enforce {
    file_line { 'inactive password lock':
      ensure             => present,
      path               => '/etc/default/useradd',
      match              => '^INACTIVE=',
      line               => "INACTIVE=${inactive_days}",
      append_on_no_match => true,
    }
  }
}
