# @summary
#    Ensure off-load of audit logs.
#
# The operating system must configure the au-remote plugin to off-load audit logs using the audisp-remote daemon.
#
# Rationale:
# Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
#
# Off-loading is a common process in information systems with limited audit storage capacity.
#
# Without the configuration of the "au-remote" plugin, the audisp-remote daemon will not off load the logs from the 
# system being audited.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::auditd_remote_conf':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_remote_conf (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/audisp/plugins.d/au-remote.conf':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

    file_line { 'off-load-direction':
      ensure => present,
      path   => '/etc/audisp/plugins.d/au-remote.conf',
      match  => '^direction =',
      line   => 'direction = out',
      notify => Service['auditd'],
    }

    file_line { 'off-load-path':
      ensure => present,
      path   => '/etc/audisp/plugins.d/au-remote.conf',
      match  => '^path =',
      line   => 'path = /sbin/audisp-remote',
      notify => Service['auditd'],
    }

    file_line { 'off-load-type':
      ensure => present,
      path   => '/etc/audisp/plugins.d/au-remote.conf',
      match  => '^type =',
      line   => 'type = always',
      notify => Service['auditd'],
    }
  }
}
