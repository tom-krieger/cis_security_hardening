# @summary 
#    Ensure SSH LogLevel is set to INFO 
#
# The INFO parameter specifies that login and logout activity will be logged. 
#
# Rationale:
# SSH provides several logging levels with varying amounts of verbosity. DEBUG is specifically not recommended other 
# than strictly for debugging SSH communications since it provides so much data that it is difficult to identify 
# important security information. INFO level is the basic level that only records login activity of SSH users. In many 
# situations, such as Incident Response, it is important to determine when a particular user was active on a system. 
# The logout record can eliminate those users who disconnected, which helps narrow the field.
#
# @param enforce
#    Enforce the rule
#
# @param log_level
#    SSHD loglevel.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_loglevel':
#       enforce => true,
#       loglevel => 'INFO',
#   }
#
# @api private
class cis_security_hardening::rules::sshd_loglevel (
  Boolean $enforce                   = false,
  Enum['INFO', 'VERBOSE'] $log_level = 'INFO',
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-loglevel':
      ensure => present,
      path   => $path,
      line   => "LogLevel ${log_level}",
      match  => '^#?LogLevel.*',
      notify => Exec['reload-sshd'],
    }
  }
}
