# @summary
#    Ensure all AppArmor Profiles are in enforce or complain mode (Automated)
#
# AppArmor profiles define what resources applications are able to access.
#
# Rationale:
# Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter 
# than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies 
# that exist on the system are activated.
#
# @param enforce
#   Enforce the rule.
#
# @param mode
#   Run apparmor in complain or enforce mode.
#
# @example
#   class { 'cis_security_hardening::rules::apparmor_profiles':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::apparmor_profiles_enforcing (
  Boolean $enforce                  = false,
  Enum['enforce', 'complain'] $mode = 'enforce',
) {
  if  $enforce and
  fact('cis_security_hardening.apparmor.profiles_status') == false {
    $cmd = "aa-${mode} /etc/apparmor.d/*"

    exec { "apparmor ${mode}":
      command => $cmd,
      path    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
    }
  }
}
