# @summary 
#    Ensure core dumps are restricted 

#
# A core dump is the memory of an executable program. It is generally used to determine why a 
# program aborted. It can also be used to glean confidential information from a core file. The 
# system provides the ability to set a soft limit for core dumps, but this can be overridden 
# by the user.
#
# Rationale:
# Setting a hard limit on core dumps prevents users from overriding the soft variable. If core 
# dumps are required, consider setting limits for user groups (see limits.conf(5) ). In addition, 
# setting the fs.suid_dumpable variable to 0 will prevent setuid programs from dumping core.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::restrict_core_dumps':
#      enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::restrict_core_dumps (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/security/limits.d/50-restrict-coredumps.conf':
      ensure  => file,
      content => '*          hard    core     0',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
    }

    sysctl { 'fs.suid_dumpable':
      ensure    => present,
      permanent => 'yes',
      value     => 0,
    }

    $installed = fact('cis_security_hardening.systemd-coredump') ? {
      'yes'   => true,
      default => false,
    }

    if  (($facts['os']['family'].downcase() == 'suse') and $installed) or
    ($facts['os']['family'].downcase() == 'redhat') or
    ($facts['os']['name'].downcase() == 'rocky')  or ($facts['os']['name'].downcase() == 'almalinux') {
      file_line { 'systemd-coredump-storage':
        path => '/etc/systemd/coredump.conf',
        line => 'Storage=none',
      }

      file_line { 'systemd-coredump-process-max':
        path => '/etc/systemd/coredump.conf',
        line => 'ProcessSizeMax=0',
      }
    }
  } elsif $facts['os']['name'].downcase() == 'ubuntu' and $facts['os']['release']['major'] >= '22' {
    package { 'apport':
      ensure => purged,
    }
  }
}
