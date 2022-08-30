# @summary
#    Ensure all AppArmor Profiles are enforcing 
#
# AppArmor profiles define what resources applications are able to access.
#
# Rationale:
# Security configuration requirements vary from site to site. Some sites may mandate a policy 
# that is stricter than the default policy, which is perfectly acceptable. This item is intended 
# to ensure that any policies that exist on the system are activated.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::apparmor_profiles':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::apparmor_profiles (
  Boolean $enforce = false,
) {
  if $enforce {
    $profiles = fact('cis_security_hardening.apparmor.profiles')
    $enforced = fact('cis_security_hardening.apparmor.profiles_enforced')
    if $profiles != $enforced {
      exec { 'apparmor enforce':
        command => 'aa-enforce /etc/apparmor.d/*',
        path    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
      }
    }
  }
}
