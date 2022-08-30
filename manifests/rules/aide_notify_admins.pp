# @summary
#    Ensure System Administrator are notified of changes to the baseline configuration or anomalies
#
# The Ubuntu operating system must notify designated personnel if baseline configurations are changed 
# in an unauthorized manner. The file integrity tool must notify the System Administrator when changes 
# to the baseline configuration or anomalies
#
# Rationale:
# Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or 
# allow unauthorized access to the operating system. Changes to operating system configurations can have 
# unintended side effects, some of which may be relevant to security.
#
# Detecting such changes and providing an automated response can help avoid unintended, negative consequences 
# that could ultimately affect the security state of the operating system. The operating system's IMO/ISSO 
# and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification 
# of a configuration item.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::aide_notify_admins':
#     enforce => true
#   }
#
# @api public
class cis_security_hardening::rules::aide_notify_admins (
  Boolean $enforce = false,
) {
  if $enforce {
    $file = $facts['operatingsystem'].downcase() ? {
      'debian' => '/etc/default/aide',
      'ubuntu' => '/etc/default/aide',
      default  => '/etc/sysconfig/aide',
    }

    file_line { 'set silentreports to no':
      ensure             => present,
      path               => $file,
      match              => '^#?SILENTREPORTS',
      line               => 'SILENTREPORTS=no',
      append_on_no_match => true,
    }
  }
}
