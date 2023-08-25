# @summary 
#    Ensure lockout for failed password attempts is configured 
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
# @param fail_interval
#    Time interval for failed login attempts counted for lockout.
#
# @param lockout_root
#    Flag if root should be locked on failed logins.
#
# @param lock_dir
#    Faillock direcrory to use.
#
# @example
#   class { 'cis_security_hardening::rules::pam_lockout':
#       enforce => true,
#       lockouttime => 300,
#   }
#
# @api private
class cis_security_hardening::rules::pam_lockout (
  Boolean $enforce               = false,
  Integer $attempts              = 3,
  Integer $lockouttime           = 900,
  Integer $fail_interval         = 0,
  Boolean $lockout_root          = false,
  Stdlib::Absolutepath $lock_dir = '/var/log/faillock',
) {
  if $enforce {
    $services = [
      'system-auth',
      'password-auth',
    ]

    case $facts['os']['family'].downcase() {
      'redhat': {
        $profile = fact('cis_security_hardening.authselect.profile')

        if $profile != undef and $profile != 'none' {
          $pf_path = "/etc/authselect/custom/${profile}"
        } else {
          $pf_path = ''
        }

        if $facts['os']['release']['major'] > '7' {
          if $facts['os']['release']['major'] == '8' {
            $services.each | $service | {
              $pf_file = "${pf_path}/${service}"

              if $pf_path != '' {
                file_line { "update pam lockout ${service}":
                  path   => $pf_file,
                  line   => "auth         required                                     pam_faillock.so preauth silent deny=${attempts} unlock_time=${lockouttime}  {include if \"with-faillock\"}", #lint:ignore:140chars
                  match  => '^auth\s+required\s+pam_faillock.so\s+preauth\s+silent',
                  notify => Exec['authselect-apply-changes'],
                }
              }
            }
          }

          file_line { 'faillock_fail_interval':
            ensure             => present,
            path               => '/etc/security/faillock.conf',
            match              => '^fail_interval =',
            line               => "fail_interval = ${lockouttime}",
            append_on_no_match => true,
          }

          file_line { 'faillock_deny':
            ensure             => present,
            path               => '/etc/security/faillock.conf',
            match              => '^deny =',
            line               => "deny = ${attempts}",
            append_on_no_match => true,
          }

          file_line { 'faillock_fail_unlock_time':
            ensure             => present,
            path               => '/etc/security/faillock.conf',
            match              => '^unlock_time =',
            line               => "unlock_time = ${lockouttime}",
            append_on_no_match => true,
          }

          file_line { 'faillock_dir':
            ensure             => present,
            path               => '/etc/security/faillock.conf',
            match              => '^dir =',
            line               => "dir = ${lock_dir}",
            append_on_no_match => true,
          }

          file_line { 'faillock_silent':
            ensure             => present,
            path               => '/etc/security/faillock.conf',
            match              => '^silent',
            line               => 'silent',
            append_on_no_match => true,
          }

          file_line { 'faillock_audit':
            ensure             => present,
            path               => '/etc/security/faillock.conf',
            match              => '^audit',
            line               => 'audit',
            append_on_no_match => true,
          }

          if $lockout_root {
            file_line { 'faillock_even_deny_root':
              ensure             => present,
              path               => '/etc/security/faillock.conf',
              match              => '^even_deny_root',
              line               => 'even_deny_root',
              append_on_no_match => true,
            }
          }
        }

        if ($facts['os']['release']['major'] == '7') {
          if ($fail_interval > 0) {
            $fail = "fail_interval=${fail_interval} "
          } else {
            $fail = ''
          }
          $root_lockout = $lockout_root ? {
            true  => 'even_deny_root ',
            false => '',
          }

          if $fail_interval > 0 {
            $arguments = ['preauth', 'silent', 'audit', "deny=${attempts}", "unlock_time=${lockouttime}", "fail_interval=${fail_interval}"]
            $faillock_args = ['preauth', 'silent','audit', "deny=${attempts}", "unlock_time=${lockouttime}", "fail_interval=${fail_interval}"] #lint:ignore:140chars
            $arguments2 = ['authfail', 'audit', "deny=${attempts}", "unlock_time=${lockouttime}", "fail_interval=${fail_interval}"]
          } else {
            $arguments = ['preauth', 'silent', 'audit', "deny=${attempts}", "unlock_time=${lockouttime}"]
            $faillock_args = ['preauth', 'silent','audit', "deny=${attempts}", "unlock_time=${lockouttime}"]
            $arguments2 = ['authfail', 'audit', "deny=${attempts}", "unlock_time=${lockouttime}"]
          }

          if $lockout_root {
            $real_arguments = concat($arguments, 'even_deny_root')
            $real_arguments2 = concat($arguments2, 'even_deny_root')
            $real_faillock_args = concat($faillock_args, 'even_deny_root')
          } else {
            $real_arguments = $arguments
            $real_arguments2 = $arguments2
            $real_faillock_args = $faillock_args
          }

          file_line { 'use pam access':
            ensure             => present,
            path               => '/etc/sysconfig/authconfig',
            match              => '^USEPAMACCESS=',
            line               => 'USEPAMACCESS=yes',
            append_on_no_match => true,
            notify             => Exec['configure faillock'],
          }

          file_line { 'faillock args':
            ensure             => present,
            path               => '/etc/sysconfig/authconfig',
            match              => '^FAILLOCKARGS=',
            line               => "FAILLOCKARGS=\"${join($real_faillock_args, ' ')}\"",
            append_on_no_match => true,
            notify             => Exec['configure faillock'],
          }

          exec { 'configure faillock':
            command     => "authconfig --faillockargs=\"${join($real_faillock_args, ' ')}\" --enablefaillock --update", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
            path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            refreshonly => true,
            notify      => Exec['authconfig-apply-changes'],
          }

          $services.each | $service | {
            Pam { "account-faillock-${service}":
              ensure  => present,
              service => $service,
              type    => 'account',
              control => 'required',
              module  => 'pam_faillock.so',
            }

            Pam { "disable-nullok-${service}":
              ensure    => present,
              service   => $service,
              type      => 'auth',
              module    => 'pam_unix.so',
              arguments => ['try_first_pass'],
            }
          }
        }
      }
      'debian': {
        if ($facts['os']['name'].downcase() == 'debian' and
        $facts['os']['release']['major'] > '10') or
        ($facts['os']['name'].downcase() == 'ubuntu' and
        $facts['os']['release']['major'] >= '22') {
          require cis_security_hardening::rules::pam_pw_requirements
          file { '/etc/pam.d/common-auth':
            ensure  => file,
            source  => 'puppet:///modules/cis_security_hardening/pam_lockout/debian/common-auth',
            owner   => 'root',
            group   => 'root',
            mode    => '0644',
            require => Class['cis_security_hardening::rules::pam_pw_requirements'],
          }

          file { '/etc/pam.d/common-account':
            ensure  => file,
            source  => 'puppet:///modules/cis_security_hardening/pam_lockout/debian/common-account',
            owner   => 'root',
            group   => 'root',
            mode    => '0644',
            require => Class['cis_security_hardening::rules::pam_pw_requirements'],
          }

          file_line { 'faillock_fail_interval':
            ensure             => present,
            path               => '/etc/security/faillock.conf',
            match              => '^fail_interval =',
            line               => "fail_interval = ${lockouttime}",
            append_on_no_match => true,
          }

          file_line { 'faillock_deny':
            ensure             => present,
            path               => '/etc/security/faillock.conf',
            match              => '^deny =',
            line               => "deny = ${attempts}",
            append_on_no_match => true,
          }

          file_line { 'faillock_fail_unlock_time':
            ensure             => present,
            path               => '/etc/security/faillock.conf',
            match              => '^unlock_time =',
            line               => "unlock_time = ${lockouttime}",
            append_on_no_match => true,
          }
        } else {
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
