# @summary 
#    Ensure the operating system is configured to enable DAC on symlinks
#
# The operating system must enable kernel parameters to enforce discretionary access control on symlinks.
#
# Rationale:
# Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have 
# discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually 
# acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who
# will have access to objects they control. An example of DAC includes user-controlled file permissions.
#
# When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can 
# take with information for which they have already been granted access. Thus, subjects that have been granted access to information 
# are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject 
# that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints 
# of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another 
# subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the 
# same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside the control of 
# the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional 
# definitions of discretionary access control require identity-based access control, that limitation is not required for this use of 
# discretionary access control.
#
# By enabling the fs.protected_symlinks kernel parameter, symbolic links are permitted to be followed only when outside a sticky 
# world-writable directory, or when the UID of the link and follower match, or when the directory owner matches the symlink's owner.
#
# Disallowing such symlinks helps mitigate vulnerabilities based on insecure file system accessed by privileged programs, avoiding an 
# exploitation vector exploiting unsafe use of open() or creat().
#
# Satisfies: SRG-OS-000312-GPOS-00122, SRG-OS-000312-GPOS-00123, SRG-OS-000312- GPOS-00124, SRG-OS-000324-GPOS-00125
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::dac_on_symlinks':
#     enforce => true,
#   }
#
# @api privare
class cis_security_hardening::rules::dac_on_symlinks (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'fs.protected_symlinks':
        value  => 1,
        notify => Exec['reload-sysctl-system'],
    }
  }
}
