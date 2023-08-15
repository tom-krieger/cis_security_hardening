# @summary 
#    Ensure kernel module loading and unloading is collected 
#
# Monitor the loading and unloading of kernel modules. The programs insmod (install a kernel module), 
# rmmod (remove a kernel module), and modprobe (a more sophisticated program to load and unload modules, 
# as well as some other features) control loading and unloading of modules. The init_module (load a module) 
# and delete_module (delete a module) system calls control loading and unloading of modules. Any execution 
# of the loading and unloading module programs and system calls will trigger an audit record with an 
# identifier of "modules".
#
# Rationale:
# Monitoring the use of insmod , rmmod and modprobe could provide system administrators with evidence that 
# an unauthorized user loaded or unloaded a kernel module, possibly compromising the security of the system. 
# Monitoring of the init_module and delete_module system calls would reflect an unauthorized user attempting 
# to use a different program to load and unload modules.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_modules':
#             enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_modules (
  Boolean $enforce                 = false,
) {
  if $enforce {
    concat::fragment { 'watch modules rule 1':
      order   => '71',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /sbin/insmod -p x -k modules',
    }

    concat::fragment { 'watch modules rule 2':
      order   => '72',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /sbin/rmmod -p x -k modules',
    }

    concat::fragment { 'watch modules rule 3':
      order   => '73',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /sbin/modprobe -p x -k modules',
    }

    if $facts['os']['family'].downcase == 'redhat' and $facts['os']['release']['major'] >= '9' {
      $key = '-F key=modules'
    } else {
      $key = '-k modules'
    }

    if  $facts['os']['architecture'] == 'x86_64' or $facts['os']['architecture'] == 'amd64' {
      concat::fragment { 'watch modules rule 4':
        order   => '74',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => "-a always,exit -F arch=b64 -S init_module -S delete_module ${key}",
      }
    }
    concat::fragment { 'watch modules rule 5':
      order   => '75',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F arch=b32 -S init_module -S delete_module ${key}",
    }
  }
}
