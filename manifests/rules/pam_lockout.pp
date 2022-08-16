# @summary 
#    Ensure lockout for failed password attempts is configured (Automated)
#
# Lock out users after n unsuccessful consecutive login attempts. The first sets of changes are made to the PAM 
# configuration files. The second set of changes are applied to the program specific PAM configuration file. The 
# second set of changes must be applied to each program that will lock out users. Check the documentation for each 
# secondary program for instructions on how to configure them to work with PAM.
#
# Set the lockout number to the policy in effect at your site.
#
# Rationale:
# Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against 
# your systems.
#
# @param enforce
#    Enforce the rule
#
# @param attempts
#    Lock account after this number of failed logins
#
# @param lockouttime
#    Lockout the account for this number of seconds
#
# @example
#   class { 'cis_security_hardening::rules::pam_lockout':
#       enforce => true,
#       lockouttime => 300,
#   }
#
# @api private
class cis_security_hardening::rules::pam_lockout (
  Boolean $enforce     = false,
  Integer $attempts    = 3,
  Integer $lockouttime = 900,
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

        $services.each | $service | {
          $pf_file = "${pf_path}/${service}"

          if  $facts['operatingsystemmajrelease'] > '7' and
          $pf_path != '' {
            file_line { "update pam lockout ${service}":
              path   => $pf_file,
              line   => "auth         required                                     pam_faillock.so preauth silent deny=${attempts} unlock_time=${lockouttime}  {include if \"with-faillock\"}", #lint:ignore:140chars
              match  => '^auth\s+required\s+pam_faillock.so\s+preauth\s+silent',
              notify => Exec['authselect-apply-changes'],
            }
          }
        }

        if ($facts['operatingsystemmajrelease'] == '7') {
          exec { 'configure faillock':
            command => "authconfig --faillockargs=\"preauth silent audit deny=${attempts} unlock_time=${lockouttime}\" --enablefaillock --updateall", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
            path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            onlyif  => "test -z \"\$(grep -E \"auth\\s+required\\s+pam_faillock.so.*deny=${attempts} unlock_time=${lockouttime}\" /etc/pam.d/system-auth /etc/pam.d/password-auth)\"", #lint:ignore:140chars
          }
        }
      }
      'debian': {
        if $lockouttime == 0 {
          $args = ['onerr=fail', 'audit', 'silent', "deny=${attempts}"]
        } else {
          $args = ['onerr=fail', 'audit', 'silent', "deny=${attempts}", "unlock_time=${lockouttime}"]
        }
        Pam { 'pam-common-auth-require-tally2':
          ensure    => present,
          service   => 'common-auth',
          type      => 'auth',
          control   => 'required',
          module    => 'pam_tally2.so',
          arguments => $args,
        }

        Pam { 'pam-common-account-requisite-deny':
          ensure  => present,
          service => 'common-account',
          type    => 'account',
          control => 'requisite',
          module  => 'pam_deny.so',
        }

        Pam { 'pam-common-account-require-tally2':
          ensure  => present,
          service => 'common-account',
          type    => 'account',
          control => 'required',
          module  => 'pam_tally2.so',
        }
      }
      'suse': {
        Pam { 'pam-auth-required':
          ensure    => present,
          service   => 'login',
          type      => 'auth',
          control   => 'required',
          module    => 'pam_tally2.so',
          arguments => ["deny=${attempts}", 'onerr=fail', "unlock_time=${lockouttime}"],
          position  => 'after *[type="auth" and module="pam_env.so"]',
        }

        Pam { 'pam-account-required':
          ensure  => present,
          service => 'common-account',
          type    => 'account',
          control => 'required',
          module  => 'pam_tally2.so',
        }
      }
      default: {
        # nothing to be done yet
      }
    }
  }
}
