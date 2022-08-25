# @summary 
#    Ensure password creation requirements are configured 
#
# The pam_pwquality.so module checks the strength of passwords. It performs checks such as making sure a password is not a 
# dictionary word, it is a certain length, contains a mix of characters (e.g. alphabet, numeric, other) and more. The 
# following are definitions of the pam_pwquality .so options.
#
# - try_first_pass - retrieve the password from a previous stacked PAM module. If not available, then prompt the user for a password.
# - retry=3 - Allow 3 tries before sending back a failure.
#
# The following options are set in the /etc/security/pwquality.conf file:
# - minlen = 14 - password must be 14 characters or more
# - dcredit = -1 - provide at least one digit
# - ucredit = -1 - provide at least one uppercase character
# - ocredit = -1 - provide at least one special character
# - lcredit = -1 - provide at least one lowercase character
#
# The settings shown above are one possible policy. Alter these values to conform to your own organization's password policies.
#
# Rationale:
# Strong passwords protect systems from being hacked through brute force methods.
#
# @param enforce
#    Enforce the rule
#
# @param minlen
#    Minimal password length
#
# @param dcredit
#    Minimum number of digits a password must contain
#
# @param ucredit
#    Minimum number of upper case characters a apassword mt contain
#
# @param ocredit
#    Minimum number of special characters a password must contain
#
# @param lcredit
#    Minimum number of lower case characters a password must contain
#
# @param minclass
#    Minimum to provide character classes (only used for Redhat 8, ignored in oler RedHat versios). 
#    Will be ignored if value is -1. Instead *credit values are used.
#
# @param retry
#    allowed retries when password is wrong
#
# @param dictcheck
#   Ensure passwords can not use dictonary words
#
# @param difok
#    Number of characters to change.
#
# @example
#   class { 'cis_security_hardening::rules::pam_pw_requirements':
#       enforce => true,
#       retry => 3,
#   }
#
# @api private
class cis_security_hardening::rules::pam_pw_requirements (
  Boolean $enforce   = false,
  Integer $minlen    = 14,
  Integer $dcredit   = -1,
  Integer $ucredit   = -1,
  Integer $ocredit   = -1,
  Integer $lcredit   = -1,
  Integer $minclass  = -1,
  Integer $retry     = 3,
  Boolean $dictcheck = false,
  Integer $difok     = 0,
) {
  if $enforce {
    $services = [
      'system-auth',
      'password-auth',
    ]

    case $facts['osfamily'].downcase() {
      'redhat': {
        if ($facts['operatingsystemmajrelease'] > '6') {
          file_line { 'pam minlen':
            ensure             => 'present',
            path               => '/etc/security/pwquality.conf',
            line               => "minlen = ${minlen}",
            match              => '^#?minlen',
            append_on_no_match => true,
          }

          if ($minclass != -1) and ($facts['operatingsystemmajrelease'] > '7') {
            file_line { 'pam minclass':
              ensure             => 'present',
              path               => '/etc/security/pwquality.conf',
              line               => "minclass = ${minclass}",
              match              => '^#?minclass',
              append_on_no_match => true,
            }
          } else {
            file_line { 'pam dcredit':
              ensure             => 'present',
              path               => '/etc/security/pwquality.conf',
              line               => "dcredit = ${dcredit}",
              match              => '^#?dcredit',
              append_on_no_match => true,
            }

            file_line { 'pam ucredit':
              ensure             => 'present',
              path               => '/etc/security/pwquality.conf',
              line               => "ucredit = ${ucredit}",
              match              => '^#?ucredit',
              append_on_no_match => true,
            }

            file_line { 'pam ocredit':
              ensure             => 'present',
              path               => '/etc/security/pwquality.conf',
              line               => "ocredit = ${ocredit}",
              match              => '^#?ocredit',
              append_on_no_match => true,
            }

            file_line { 'pam lcredit':
              ensure             => 'present',
              path               => '/etc/security/pwquality.conf',
              line               => "lcredit = ${lcredit}",
              match              => '^#?lcredit',
              append_on_no_match => true,
            }

            if $dictcheck {
              file_line { 'pam dictcheck':
                ensure             => 'present',
                path               => '/etc/security/pwquality.conf',
                line               => 'dictcheck = 1',
                match              => '^#?dictcheck',
                append_on_no_match => true,
              }
            }

            if $difok != 0 {
              file_line { 'pam difok':
                ensure             => 'present',
                path               => '/etc/security/pwquality.conf',
                line               => "difok = ${difok}",
                match              => '^#?difok',
                append_on_no_match => true,
              }
            }
          }
        }

        $profile = fact('cis_security_hardening.authselect.profile')
        if $profile != undef and $profile != 'none' {
          $pf_path = "/etc/authselect/custom/${profile}"
        } else {
          $pf_path = ''
        }

        $services.each | $service | {
          if ($facts['operatingsystemmajrelease'] > '7') {
            if $pf_path != '' {
              $pf_file = "${pf_path}/${service}"

              Pam { "authselect configure pw requirements in ${service}":
                ensure    => present,
                service   => $service,
                type      => 'password',
                control   => 'requisite',
                module    => 'pam_pwquality.so',
                arguments => ['try_first_pass', "retry=${retry}",'enforce-for-root',"remember=${cis_security_hardening::rules::pam_old_passwords::oldpasswords}"], #lint:ignore:140chars
                target    => $pf_path,
                notify    => Exec['authselect-apply-changes'],
              }

              # exec { "update authselect config enforce for root ${service}":
              #   command => "sed -ri 's/^\\s*(password\\s+requisite\\s+pam_pwquality.so\\s+)(.*)$/\\1\\2 enforce-for-root/' ${pf_file}", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
              #   path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              #   onlyif  => "test -z \"\$(grep -E '^\\s*password\\s+requisite\\s+pam_pwquality.so\\s+.*enforce-for-root\\s*.*\$' ${pf_file})\"", #lint:ignore:140chars
              #   notify  => Exec['authselect-apply-changes'],
              # }

              # exec { "update authselect config retry ${service}":
              #   command => "sed -ri '/pwquality/s/retry=\\S+/retry=${retry}/' ${pf_file}", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
              #   path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              #   onlyif  => "test -z \"\$(grep -E '^\\s*password\\s+requisite\\s+pam_pwquality.so\\s+.*\\s+retry=\\S+\\s*.*\$' ${pf_file})\"", #lint:ignore:140chars
              #   notify  => Exec['authselect-apply-changes'],
              # }

              # exec { "update authselect config retry (2) ${service}":
              #   command => "sed -ri 's/^\\s*(password\\s+requisite\\s+pam_pwquality.so\\s+)(.*)$/\\1\\2 retry=${retry}/' ${pf_file}", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
              #   path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              #   onlyif  => "test -z \"\$(grep -E '^\\s*password\\s+requisite\\s+pam_pwquality.so\\s+.*\\s+retry=\\S+\\s*.*\$' ${pf_file})\"", #lint:ignore:140chars
              #   notify  => Exec['authselect-apply-changes'],
              # }
            }
          } elsif($facts['operatingsystemmajrelease'] == '7') {
            Pam { "pam-${service}-requisite":
              ensure    => present,
              service   => $service,
              type      => 'password',
              control   => 'requisite',
              module    => 'pam_pwquality.so',
              arguments => ['try_first_pass', 'retry=3'],
            }
          } else {
            Pam { "pam-${service}-requisite":
              ensure    => present,
              service   => $service,
              type      => 'password',
              control   => 'requisite',
              module    => 'pam_cracklib.so',
              arguments => ['try_first_pass', 'retry=3', "minlen=${minlen}", "dcredit=${dcredit}",
              "ucredit=${ucredit}", "ocredit=${ocredit}", "lcredit=${lcredit}"],
            }
          }
        }
      }
      'debian' : {
        ensure_packages(['libpam-pwquality'], {
            ensure => installed,
        })

        file_line { 'pam minlen':
          ensure             => 'present',
          path               => '/etc/security/pwquality.conf',
          line               => "minlen = ${minlen}",
          match              => '^#?minlen',
          append_on_no_match => true,
        }

        file_line { 'pam minclass':
          ensure             => 'present',
          path               => '/etc/security/pwquality.conf',
          line               => "minclass = ${minclass}",
          match              => '^#?minclass',
          append_on_no_match => true,
        }

        file_line { 'pam enforcing':
          ensure             => 'present',
          path               => '/etc/security/pwquality.conf',
          line               => 'enforcing = 1',
          match              => '^#?enforcing',
          append_on_no_match => true,
        }

        file_line { 'pam dcredit':
          ensure             => 'present',
          path               => '/etc/security/pwquality.conf',
          line               => "dcredit = ${dcredit}",
          match              => '^#?dcredit',
          append_on_no_match => true,
        }

        file_line { 'pam ucredit':
          ensure             => 'present',
          path               => '/etc/security/pwquality.conf',
          line               => "ucredit = ${ucredit}",
          match              => '^#?ucredit',
          append_on_no_match => true,
        }

        file_line { 'pam ocredit':
          ensure             => 'present',
          path               => '/etc/security/pwquality.conf',
          line               => "ocredit = ${ocredit}",
          match              => '^#?ocredit',
          append_on_no_match => true,
        }

        file_line { 'pam lcredit':
          ensure             => 'present',
          path               => '/etc/security/pwquality.conf',
          line               => "lcredit = ${lcredit}",
          match              => '^#?lcredit',
          append_on_no_match => true,
        }

        if $difok != 0 {
          file_line { 'pam difok':
            ensure             => 'present',
            path               => '/etc/security/pwquality.conf',
            line               => "difok = ${difok}",
            match              => '^#?difok',
            append_on_no_match => true,
          }
        }

        if $dictcheck {
          file_line { 'pam dictcheck':
            ensure             => 'present',
            path               => '/etc/security/pwquality.conf',
            line               => 'dictcheck = 1',
            match              => '^#dictcheck',
            append_on_no_match => true,
          }
        }

        Pam { 'pam-common-password-requisite':
          ensure    => present,
          service   => 'common-password',
          type      => 'password',
          control   => 'requisite',
          module    => 'pam_pwquality.so',
          arguments => ["retry=${retry}"],
        }
      }
      'suse': {
        Pam { 'pam-common-password-requisite':
          ensure    => present,
          service   => 'common-password',
          type      => 'password',
          control   => 'requisite',
          module    => 'pam_cracklib.so',
          arguments => ["retry=${retry}", "minlen=${minlen}", "dcredit=${dcredit}",
          "ucredit=${ucredit}", "ocredit=${ocredit}", "lcredit=${lcredit}"],
        }
      }
      default: {
        # nothing to do yet
      }
    }
  }
}
