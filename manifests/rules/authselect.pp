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
class cis_security_hardening::rules::authselect (
  Boolean $enforce                                        = false,
  Enum['sssd', 'nis', 'winbind', 'minimal'] $base_profile = 'sssd',
  Cis_security_hardening::Numbers_letters $custom_profile = '',
  Array $profile_options                                  = ['with-faillock'],
) {
  if $enforce {
    exec { 'create custom profile':
      command => "authselect create-profile ${custom_profile} -b ${base_profile} --symlink-meta", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test ! -d /etc/authselect/custom/${custom_profile}",
      before  => Exec['select authselect profile'],
    }

    exec { 'select authselect profile':
      command => "authselect select custom/${custom_profile} -f",   #lint:ignore:security_class_or_define_parameter_in_exec
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => ["test -d /etc/authselect/custom/${custom_profile}", "test -z \"$(authselect current | grep 'custom/${custom_profile}')\""], #lint:ignore:140chars
      returns => [0, 1],
    }

    $available_features = fact('cis_security_hardening.authselect.available_features') ? {
      undef   => [],
      default => fact('cis_security_hardening.authselect.available_features'),
    }
    $profile_options.each |$opt| {
      unless $opt =~ /^[0-9a-zA-Z\-_\.]+$/ {
        fail("Illegal profile option: ${opt}")
      }

      if $opt in $available_features {
        exec { "enable feature ${opt}":
          command => "authselect enable-feature ${opt}",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          onlyif  => ["test -d /etc/authselect/custom/${custom_profile}", "test -z \"$(authselect current | grep '${opt}')\""],
        }
      } else {
        echo { "unavailable feature ${opt}":
          message  => "authselect: unavailable feature ${opt}",
          loglevel => 'warning',
          withpath => false,
        }
      }
    }
  }
}
