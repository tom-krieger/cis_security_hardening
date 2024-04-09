# @summary
#    Ensure kernel module loading unloading and modification is collected
#
# Monitor the loading and unloading of kernel modules. All the loading / listing / dependency checking of modules is done by kmod
# via symbolic links.
#
# The following system calls control loading and unloading of modules:
# * init_module - load a module
# * finit_module - load a module (used when the overhead of using cryptographically signed modules to determine the authenticity
#   of a module can be avoided)
# * delete_module - delete a module
# * create_module - create a loadable module entry
# * query_module - query the kernel for various bits pertaining to modules
#
# Any execution of the loading and unloading module programs and system calls will trigger an audit record with an identifier of modules.
#
# Rationale:
# Monitoring the use of all the various ways to manipulate kernel module s could provide system administrators with evidence that
# an unauthorized change was made to a kernel module, possibly compromising the security of the system.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_kernel_modules':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_kernel_modules (
  Boolean $enforce = false,
) {
  if $enforce {
    $auid = $facts['os']['name'].downcase() ? {
      'rocky'     => 'unset',
      'almalinux' => 'unset',
      'debian'    => 'unset',
      'ubuntu'    => 'unset',
      default     => '4294967295',
    }
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    if $facts['os']['name'].downcase() == 'redhat' and $facts['os']['release']['major'] == '7' {
      $rule1 = "-a always,exit -S all -F path=/usr/bin/kmod -p x -F auid>=${uid} -F auid!=${auid} -k module-change"
    } elsif $facts['os']['name'].downcase() == 'redhat' and $facts['os']['release']['major'] >= '8' {
      $rule1 = "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=${uid} -F auid!=${auid} -F key=kernel_modules"
    } elsif $facts['os']['name'].downcase() == 'debian' and $facts['os']['release']['major'] > '12'{
      $rule1 = "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=${uid} -F auid!=${auid} -k kernel_modules"
    } else {
      $rule1 = "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=${uid} -F auid!=${auid} -F key=kernel_modules"
    }
    concat::fragment { 'watch kernel modules rule 1':
      order   => '204',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => $rule1,
    }
    if  $facts['os']['architecture'] == 'x86_64' or $facts['os']['architecture'] == 'amd64' {
      concat::fragment { 'watch kernel modules rule 2':
        order   => '205',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=${uid} -F auid!=${auid} -k kernel_modules", #lint:ignore:140chars
      }
    }
  }
}
