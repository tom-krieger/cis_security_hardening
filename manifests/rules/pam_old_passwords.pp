# @summary 
#    Ensure password reuse is limited (Automated)
#
# The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users 
# are not recycling recent passwords.
#
# Rationale:
# Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to 
# guess the password.
# 
# Note that these change only apply to accounts configured on the local system.
#
# @param enforce
#    Enforce the rule
#
# @param oldpasswords
#    Number of old passwords to remember
#
# @example
#   class { 'cis_security_hardening::rules::pam_old_passwords':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::pam_old_passwords (
  Boolean $enforce      = false,
  Integer $oldpasswords = 5,
) {
  if $enforce {
    $services = [
      'system-auth',
      'password-auth',
    ]

    case $facts['osfamily'].downcase() {
      'redhat': {
        $profile = fact('cis_security_hardening.authselect.profile')
        if $profile != undef and $profile != 'none' {
          $pf_path = "/etc/authselect/custom/${profile}"
        } else {
          $pf_path = ''
        }

        if ($facts['operatingsystemmajrelease'] > '7') {
          if $pf_path != '' {
            $pf_file = "${pf_path}/system-auth"

            exec { 'update authselect config for old passwords':
              command => "sed -ri 's/^\\s*(password\\s+(requisite|sufficient)\\s+(pam_pwquality\\.so|pam_unix\\.so)\\s+)(.*)(remember=\\S+\\s*)(.*)$/\\1\\4 remember=${oldpasswords} \\6/' ${pf_file} || sed -ri 's/^\\s*(password\\s+(requisite|sufficient)\\s+(pam_pwquality\\.so|pam_unix\\.so)\\s+)(.*)$/\\1\\4 remember=${oldpasswords}/' ${pf_file}", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars lint:ignore:security_password_variable_in_exec
              path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              onlyif  => "test -z '\$(grep -E '^\\s*password\\s+(sufficient\\s+pam_unix|requi(red|site)\\s+pam_pwhistory).so\\s+ ([^#]+\\s+)*remember=\\S+\s*.*\$' ${pf_file})'", #lint:ignore:140chars
              notify  => Exec['authselect-apply-changes'],
            }
          }
        } else {
          $sha512 = lookup('cis_security_hardening::rules::pam_passwd_sha512::enforce')
          if $sha512 {
            $real_arguments = ['sha512', "remember=${oldpasswords}", 'shadow', 'try_first_pass', 'use_authtok']
          } else {
            $real_arguments = ["remember=${oldpasswords}", 'shadow', 'try_first_pass', 'use_authtok']
          }

          $services.each | $service | {
            Pam { "pam-${service}-sufficient":
              ensure    => present,
              service   => $service,
              type      => 'password',
              control   => 'sufficient',
              module    => 'pam_unix.so',
              arguments => $real_arguments,
              position  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
            }
          }
        }
      }
      'debian', 'suse': {
        Pam { 'pam-common-password-requisite-pwhistory':
          ensure    => present,
          service   => 'common-password',
          type      => 'password',
          control   => 'required',
          module    => 'pam_pwhistory.so',
          arguments => ["remember=${oldpasswords}"],
        }
      }
      default: {
        # nothing to be done yet
      }
    }
  }
}
