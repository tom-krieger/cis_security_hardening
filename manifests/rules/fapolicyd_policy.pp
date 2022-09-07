# @summary
#    Ensure "fapolicyd" employs a deny-all, permit-by-exception policy
#
# The "fapolicy" module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of 
# authorized software programs.
#
# Rationale:
# The organization must identify authorized software programs and permit execution of authorized software. The process 
# used to identify software programs that are authorized to execute on organizational information systems is commonly 
# referred to as whitelisting. Utilizing a whitelist provides a configuration management method for allowing the execution 
# of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities. 
# Verification of whitelisted software occurs prior to execution or at system startup.
#
# User home directories/folders may contain information of a sensitive nature. Non- privileged users should coordinate any 
# sharing of information with an SA through shared resources.
#
# RHEL 8 operating systems ship with many optional packages. One such package is a file access policy daemon called "fapolicyd". 
# "fapolicyd" is a userspace daemon that determines access rights to files based on attributes of the process and file. It can 
# be used to either blacklist or whitelist processes or file access.
#
# Proceed with caution with enforcing the use of this daemon. Improper configuration may render the system non-functional. 
# The "fapolicyd" API is not namespace aware and can cause issues when launching or running containers.
#
# Satisfies: SRG-OS-000368-GPOS-00154, SRG-OS-000370-GPOS-00155, SRG-OS-000480- GPOS-00232
#
# @param enforce
#    Enforce the rule.
# @param permissive
#    fapolicyd should behave permissive (1) or enforcing (0).
#
# @param create_rules
#    Create a file with mountpoints as basis for rule creating.
#
# @example
#   class { 'cis_security_hardening::rules::fapolicyd_policy':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::fapolicyd_policy (
  Boolean $enforce           = false,
  Enum['0', '1'] $permissive = 1,
  Boolean $create_rules      = false,
) {
  if $enforce {
    file_line { 'fapolicyd_permissive':
      ensure             => present,
      path               => '/etc/fapolicyd/fapolicyd.conf',
      match              => '^permissive =',
      line               => "permissive = ${permissive}",
      append_on_no_match => true,
    }

    if $create_rules {
      concat { '/etc/fapolicyd/fapolicyd.mounts':
        ensure => present,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
      }
      $mps = fact('mountpoints') ? {
        undef   => {},
        default => fact('mountpoints',)
      }

      $mps.each |$mp, $data| {
        if $data['filesystem'] in ['tmpfs', 'ext4', 'ext3', 'xfs'] {
          concat::fragment { "mount-${mp}":
            content => "${mp}\n",
            target  => '/etc/fapolicyd/fapolicyd.mounts',
          }
        }
      }
    }
  }
}
