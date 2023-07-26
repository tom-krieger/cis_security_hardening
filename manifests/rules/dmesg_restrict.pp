# @summary
#    Ensure the operating system is configured to restrict access to the kernel message buffer
#
# The operating system must restrict access to the kernel message buffer. 
#
# Rationale:
# Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations 
# of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior 
# users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system 
# resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. 
# The control of information in shared resources is also commonly referred to as object reuse and residual information protection.
#
# This requirement generally applies to the design of an information technology product, but it can also apply to the configuration 
# of particular information system components that are, or use, such products. This can be verified by acceptance/validation 
# processes in DoD or other government agencies.
#
# There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information 
# system components.
#
# Restricting access to the kernel message buffer limits access to only root. This prevents attackers from gaining additional 
# system information as a non-privileged user.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class {cis_security_hardening::rules::dmesg_restrict':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::dmesg_restrict (
  Boolean $enforce = true,
) {
  if $enforce {
    sysctl {
      'kernel.dmesg_restrict':
        ensure    => present,
        permanent => 'yes',
        value     => 1,
        notify    => Exec['reload-sysctl-system'],
    }
  }
}
