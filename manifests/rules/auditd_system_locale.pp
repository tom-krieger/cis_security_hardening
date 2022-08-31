# @summary 
#    Ensure events that modify the system's network environment are collected 
#
# Record changes to network environment files or system calls. The below parameters monitor the sethostname 
# (set the systems host name) or setdomainname (set the systems domainname) system calls, and write an audit 
# event on system call exit. The other parameters monitor the /etc/issue and /etc/issue.net files (messages 
# displayed pre- login), /etc/hosts (file containing host names and associated IP addresses), 
# /etc/sysconfig/network file and /etc/sysconfig/network-scripts/ directory (containing network interface 
# scripts and configurations).
#
# Rationale:
# Monitoring sethostname and setdomainname will identify potential unauthorized changes to host and domainname 
# of a system. The changing of these names could potentially break security parameters that are set based on those 
# names. The /etc/hosts file is monitored for changes in the file that can indicate an unauthorized intruder is 
# trying to change machine associations with IP addresses and trick users and processes into connecting to 
# unintended machines. Monitoring /etc/issue and /etc/issue.net is important, as intruders could put disinformation 
# into those files and trick users into providing information to the intruder. Monitoring /etc/sysconfig/network 
# and /etc/sysconfig/network-scripts/ is important as it can show if network interfaces or scripts are being modified 
# in a way that can lead to the machine becoming unavailable or compromised. All audit records will be tagged with 
# the identifier "system-locale."
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_system_locale':   
#             enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::auditd_system_locale (
  Boolean $enforce                 = false,
) {
  if $enforce {
    $os = fact('operatingsystem') ? {
      undef   => 'unknown',
      default => fact('operatingsystem').downcase()
    }
    if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
      $content_rule7 = $os ? {
        'almalinux' => '-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale',
        'rocky'     => '-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale',
        default     => '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale',
      }
      concat::fragment { 'watch network environment rule 7':
        order   => '130',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => $content_rule7,
      }
    }
    $content_rule1 = $os ? {
      'almalinux' => '-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale',
      'rocky'     => '-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale',
      default     => '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale',
    }
    concat::fragment { 'watch network environment rule 1':
      order   => '131',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => $content_rule1,
    }
    concat::fragment { 'watch network environment rule 2':
      order   => '132',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /etc/issue -p wa -k system-locale',
    }
    concat::fragment { 'watch network environment rule 3':
      order   => '133',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /etc/issue.net -p wa -k system-locale',
    }
    concat::fragment { 'watch network environment rule 4':
      order   => '134',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /etc/hosts -p wa -k system-locale',
    }
    if $facts['osfamily'].downcase() == 'debian' {
      concat::fragment { 'watch network environment rule 5':
        order   => '135',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-w /etc/network -p wa -k system-locale',
      }
    } else {
      concat::fragment { 'watch network environment rule 5':
        order   => '135',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-w /etc/sysconfig/network -p wa -k system-locale',
      }
    }

    if $facts['operatingsystem'].downcase() == 'rocky' or $facts['operatingsystem'].downcase() == 'almalinux' {
      concat::fragment { 'watch network environment rule 6':
        order   => '135',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-w /etc/sysconfig/network-scripts -p wa -k system-locale',
      }
    }
  }
}
