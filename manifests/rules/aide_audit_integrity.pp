# @summary
#    Ensure cryptographic mechanisms are used to protect the integrity of audit tools (Automated)
#
# Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully 
# view and manipulate audit information system activity and records. Audit tools include custom queries and 
# report generators.
#
# Rationale:
# Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. 
# Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit 
# information system activity.
#
# Attackers may replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or 
# erase system activity from the audit logs.
# 
# Audit tools should be cryptographically signed in order to provide the capability to identify when the audit tools have been modified, 
# manipulated, or replaced. An example is a checksum hash of the file or files.
#
# @param enforce
#    Enforce the rule
#
# @param tools
#    Hash with auditd tools to secure with aide
#
# @example
#   class { 'cis_security_hardening::rules::aide_audit_integrity':
#       enforce => true,
#       tools => {
#        'sbin/auditctl' => 'p+i+n+u+g+s+b+acl+xattrs+sha512'
#     }
#   }
#
# @api private
class cis_security_hardening::rules::aide_audit_integrity (
  Boolean $enforce = false,
  Hash $tools      = {},
) {
  if $enforce {
    require 'cis_security_hardening::rules::auditd_package'
    case $facts[ 'os']['name'].downcase() {
      'rocky': {
        $conffile = '/etc/aide.conf'
      }
      'ubuntu': {
        if $facts['os']['release']['major'] >= '20' {
          $conffile = '/etc/aide/aide.conf'
        } else {
          $conffile = '/etc/aide.conf'
        }
      }
      default: {
        $conffile = '/etc/aide.conf'
      }
    }
    $tools.each |$tool, $data| {
      file_line { "aide tool ${tool}":
        ensure             => present,
        append_on_no_match => true,
        path               => $conffile,
        line               => "${tool} ${data}",
        match              => "^${tool}",
      }
    }
  }
}
