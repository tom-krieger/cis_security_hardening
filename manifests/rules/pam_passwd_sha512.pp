# @summary 
#    Ensure password hashing algorithm is SHA-512 
#
# The commands below change password encryption from md5 to sha512 (a much stronger hashing algorithm). All 
# existing accounts will need to perform a password change to upgrade the stored hashes to the new algorithm.
#
# Rationale:
# The SHA-512 algorithm provides much stronger hashing than MD5, thus providing additional protection to the system by 
# increasing the level of effort for an attacker to successfully determine passwords.
#
# Note that these change only apply to accounts configured on the local system.
#
# This rule is done together with sec_pam_old_passwords
#
# @param enforce
#    Enforce the rule 
#
# @example
#   class { 'cis_security_hardening::rules::pam_passwd_sha512':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::pam_passwd_sha512 (
  Boolean $enforce = false,
) {
  if $enforce {
    $services = [
      'system-auth',
      'password-auth',
    ]

    case $facts['os']['family'].downcase() {
      'redhat': {
        if $facts['os']['release']['major'] > '7' {
          $profile = fact('cis_security_hardening.authselect.profile')
          if $profile != undef and $profile != 'none' {
            $pf_path = "/etc/authselect/custom/${profile}"

            $services.each | $service | {
              $pf_file = "${pf_path}/${service}"

              exec { "update authselect config for sha512 ${service}":
                command => "sed -ri 's/^\\s*(password\\s+sufficient\\s+pam_unix.so\\s+)(.*)$/\\1\\2 sha512/' ${pf_file}",
                path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                onlyif  => "test -z \"\$(grep -E '^\\s*password\\s+sufficient\\s+pam_unix.so\\s+.*sha512\\s*.*\$' ${pf_file})\"",
                notify  => Exec['authselect-apply-changes'],
              }
            }
          }
        } else {
          exec { 'authconfig-passalgo-sha512':
            command     => 'authconfig --passalgo=sha512 --updateall',
            path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            refreshonly => true,
          }
          file_line { 'password algorithm sha512':
            ensure             => present,
            path               => '/etc/sysconfig/authconfig',
            match              => '^PASSWDALGORITHM=',
            line               => 'PASSWDALGORITHM=sha512',
            append_on_no_match => true,
            notify             => Exec['authconfig-passalgo-sha512'],
          }
        }
      }
      'debian': {
        if ($facts['os']['name'].downcase() == 'debian' and $facts['os']['release']['major'] > '10') {
          $keyring = fact('cis_security_hardening.gnome_keyring.installed')
          $src_file = fact('cis_security_hardening.gnome_keyring.installed') ? {
            default  => 'puppet:///modules/cis_security_hardening/pam_lockout/debian/common-password',
            ''       => 'puppet:///modules/cis_security_hardening/pam_lockout/debian/common-password-wo-gnome-keyring',
          }
          file { '/etc/pam.d/common-password':
            ensure  => file,
            source  => $src_file,
            owner   => 'root',
            group   => 'root',
            mode    => '0644',
            require => Class['cis_security_hardening::rules::pam_pw_requirements'],
          }

          file_line { 'set crypt method':
            ensure             => present,
            path               => '/etc/login.defs',
            match              => '^ENCRYPT_METHOD',
            line               => 'ENCRYPT_METHOD yescrypt',
            append_on_no_match => true,
            require            => Class['cis_security_hardening::rules::pam_pw_requirements'],
          }
        } elsif  ($facts['os']['name'].downcase() == 'ubuntu' and $facts['os']['release']['major'] >= '22') {
          file_line { 'set crypt method':
            ensure             => present,
            path               => '/etc/login.defs',
            match              => '^ENCRYPT_METHOD',
            line               => 'ENCRYPT_METHOD yescrypt',
            append_on_no_match => true,
            require            => Class['cis_security_hardening::rules::pam_pw_requirements'],
          }
        } else {
          Pam { 'pam-common-password-unix':
            ensure           => present,
            service          => 'common-password',
            type             => 'password',
            control          => '[success=1 default=ignore]',
            control_is_param => true,
            module           => 'pam_unix.so',
            arguments        => ['sha512'],
          }
        }
      }
      default: {
        # nothing to do yet
      }
    }
  }
}
