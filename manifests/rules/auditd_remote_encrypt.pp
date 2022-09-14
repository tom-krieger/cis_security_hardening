# @summary 
#    Ensure audit logs on separate system are encrypted
#
# The operating system must encrypt the transfer of audit records off-loaded onto a different system or media from 
# the system being audited and encrypted the records.
#
# Rationale:
# Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
#
# Off-loading and encrypting is a common process in information systems with limited audit storage capacity.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_remote_encrypt':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_remote_encrypt (
  Boolean $enforce = false,
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

    file_line { 'auditd remote encrypt':
      ensure             => present,
      path               => $file,
      line               => 'enable_krb5 = yes',
      match              => '^enable_krb5 =',
      append_on_no_match => true,
      require            => File[$file],
    }
  }
}
