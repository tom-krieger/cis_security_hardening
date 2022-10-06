# @summary
#    Ensure GRUB 2 is configured to disable vsyscalls
#
# The operating system must disable virtual syscalls. 
#
# Rationale:
# Syscalls are special routines in the Linux kernel, which userspace applications ask to do privileged tasks. 
# nvoking a system call is an expensive operation because the processor must interrupt the currently executing 
# task and switch context to kernel mode and then back to userspace after the system call completes. Virtual 
# syscalls map into user space a page that contains some variables and the implementation of some system calls. 
# This allows the system calls to be executed in userspace to alleviate the context switching expense.
#
# Virtual syscalls provide an opportunity of attack for a user who has control of the return instruction pointer. 
# Disabling vsyscalls help to prevent return oriented programming (ROP) attacks via buffer overflows and overruns. 
# If the system intends to run containers based on RHEL 6 components, then virtual syscalls will need to be enabled 
# so the components function properly.
# 
# Satisfies: SRG-OS-000134-GPOS-00068, SRG-OS-000433-GPOS-00192
# 
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::grub_vsyscall':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::grub_vsyscall (
  Boolean $enforce = false,
) {
  if $enforce {
    kernel_parameter { 'vsyscall':
      value  => 'none',
      notify => Exec['grub2-mkconfig'],
    }
  }
}
