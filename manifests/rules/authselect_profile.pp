# @summary 
#    Create custom authselect profile (Scored)
#
# A custom profile can be created by copying and customizing one of the default profiles. The default 
# profiles include: sssd, winbind, or the nis.
#
# Rationale:
# A custom profile is required to customize many of the pam options.
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param custom_profile
#    name of the custom profile to create
#
# @param base_profile
#    Base profile to use for custom profile creation
#
# @example
#   class { 'cis_security_hardening::rules::authselect_profile':   
#             enforce => true,
#             custom_profile => 'testprofile',
#             base_profile => 'sssd',
#   }
#
# @api private
class cis_security_hardening::rules::authselect_profile (
  Boolean $enforce                                        = false,
  Cis_security_hardening::Numbers_letters $custom_profile = '',
  Enum['sssd', 'nis', 'winbind', 'minimal'] $base_profile = 'sssd',
) {
  if $enforce {
    $cmd = "authselect create-profile ${custom_profile} -b ${base_profile} --symlink-meta"

    exec { 'set custom profile':
      command => $cmd,
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test ! -d /etc/authselect/custom/${custom_profile}",
    }
  }
}
