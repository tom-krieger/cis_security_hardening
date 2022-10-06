# @summary
#    Ensure the operating system has the policycoreutils package installed
#
# The operating system must have the policycoreutils package installed. 
#
# Rationale:
# Without verification of the security functions, security functions may not operate correctly and the failure may 
# go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system 
# responsible for enforcing the system security policy and supporting the isolation of code and data on which the 
# protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring 
# access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection 
# parameters.
#
# Policycoreutils contains the policy core utilities that are required for basic operation of an SELinux-enabled system. 
# These utilities include load_policy to load SELinux policies, setfile to label filesystems, newrole to switch roles, 
# and run_init to run "/etc/init.d" scripts in the proper context.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::policycoreutils':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::policycoreutils (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['policycoreutils'], {
        ensure => installed,
    })
  }
}
