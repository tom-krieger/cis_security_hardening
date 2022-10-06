# @summary
#    Ensure audit event multiplexor is configured to off-load audit logs onto a different system or storage media from the system being 
#    audited
#
# The operating system audit event multiplexor must be configured to off-load audit logs onto a different system or storage media from 
# the system being audited.
#
# Rationale:
# Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
#
# Off-loading is a common process in information systems with limited audit storage capacity.
#
# Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224
#
# @param enforce
#    Enforce the rule
# @param remote_server
#    IP address of the remote server sending logs to.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_remote':
#     enforce => true,
#     remote_server => '1.2.3.4',
#   }
#
# @api private
class cis_security_hardening::rules::auditd_remote (
  Boolean $enforce                    = false,
  Stdlib::IP::Address $remote_server  = '1.2.3.4',
) {
  if $enforce {
    $file = $facts['os']['family'].downcase() ? {
      'redhat' => '/etc/audisp/audisp-remote.conf',
      default  => '/etc/audisp/plugins.d/au-remote.conf',
    }

    ensure_resource('file', $file, {
        ensure => file,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
    })

    file_line { 'auditd log remote':
      ensure             => present,
      path               => $file,
      line               => 'active = yes',
      match              => '^active =',
      append_on_no_match => true,
      require            => File[$file],
    }

    file_line { 'auditd log remote server':
      ensure             => present,
      path               => $file,
      line               => "remote_server = ${remote_server}",
      match              => "^remote_server = ${remote_server}",
      append_on_no_match => true,
      require            => File[$file],
    }
  }
}
