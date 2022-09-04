# @summary
#    Ensure audit system action is defined for sending errors
#
# The operating system must be configured so that the audit system takes appropriate action when there is 
# an error sending audit records to a remote system.
#
# Rationale:
# Taking appropriate action when there is an error sending audit records to a remote system will minimize 
# the possibility of losing audit records.
#
# @param enforce
#    Enforce the rule
# @param action
#    Action to take in case of network failures.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_sending_errors':
#     enforce => tru,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_sending_errors (
  Boolean $enforce                       = false,
  Enum['syslog','single','halt'] $action = 'syslog',
) {
  if $enforce {
    file { '/etc/audisp/audisp-remote.conf':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

    file_line { 'network-failure-action':
      ensure             => present,
      path               => '/etc/audisp/audisp-remote.conf',
      match              => '^network_failure_acrion =',
      line               => "network_failure_action = ${action}",
      append_on_no_match => true,
      require            => File['/etc/audisp/audisp-remote.conf'],
    }
  }
}
