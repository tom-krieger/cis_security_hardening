# @summary 
#    Select authselect profile (Scored)
#
# You can select a profile for the authselect utility for a specific host. The profile 
# will be applied to every user logging into the host.
#
# You can create and deploy a custom profile by customizing one of the default profiles, the sssd, 
# winbind, or the nis profile.
#
# Rationale:
# When you deploy a profile, the profile is applied to every user logging into the given host.
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param custom_profile
#    name of the custom profile to create
#
# @param profile_options
#    Options to use for the authselect profile
#
# @example
#   class { 'cis_security_hardening::rules::authselect_profile_select':   
#             enforce => true,
#             custom_profile => 'testprofile',
#             profile_options => ['with-sudo', 'with-faillock', 'without-nullok'],
#   }
#
# @api private
class cis_security_hardening::rules::authselect_profile_select (
  Boolean $enforce                                        = false,
  Cis_security_hardening::Numbers_letters $custom_profile = '',
  Array $profile_options                                  = [],
) {
  if $enforce {
    $profile_options.each |$opt| {
      unless $opt =~ /^[0-9a-zA-Z\-_\.]+$/ {
        fail("Illegal profile option: ${opt}")
      }
    }

    $options = join($profile_options, ' ')
    $cmd = "authselect select custom/${custom_profile} ${options} -f"
    exec { 'select authselect profile':
      command => $cmd,
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => ["test -d /etc/authselect/custom/${custom_profile}",
      "test -z \"$(authselect current | grep 'custom/${custom_profile}')\""],
      returns => [0, 1],
    }
  }
}
