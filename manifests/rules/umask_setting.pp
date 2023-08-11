# @summary 
#    Ensure default user umask is configured 
#
# The default umask determines the permissions of files created by users. The user creating the 
# file has the discretion of making their files and directories readable by others via the chmod 
# command. Users who wish to allow their files and directories to be readable by others by default 
# may choose a different default umask by inserting the umask command into the standard shell 
# configuration files ( .profile , .bashrc , etc.) in their home directories.
#
# Rationale:
# Setting a very secure default value for umask ensures that users make a conscious choice about their 
# file permissions. A default umask setting of 077 causes files and directories created by users to not 
# be readable by any other user on the system. A umask of 027 would make files and directories readable 
# by users in the same Unix group, while a umask of 022 would make files readable by every user on the system.
#
# @param enforce
#    Enforce the rule
#
# @param default_umask
#    Default umask to set.
#
# @example
#   class { 'cis_security_hardening::rules::umask_setting':
#       enforce => true,
#       default_umask => '027',
#   }
#
# @api private
class cis_security_hardening::rules::umask_setting (
  Boolean $enforce      = false,
  String $default_umask = '027',
) {
  if $enforce {
    case $facts['os']['family'].downcase() {
      'redhat': {
        if ($facts['os']['name'].downcase() == 'redhat' and $facts['os']['release']['major'] >= '9') or
        ($facts['os']['name'].downcase() == 'rocky' and $facts['os']['release']['major'] >= '9') or
        ($facts['os']['name'].downcase() == 'almalinux' and $facts['os']['release']['major'] >= '9') {
          $services = [
            'common-session',
          ]
        } else {
          $services = [
            'system-auth',
            'password-auth',
          ]
        }

        file_line { 'bashrc':
          path     => '/etc/bashrc',
          line     => "      umask ${default_umask}",
          match    => '^\s+umask\s+\d+',
          multiple => true,
        }

        file_line { 'csh.cshrc':
          path     => '/etc/csh.cshrc',
          line     => "    umask ${default_umask}",
          match    => '^\s+umask\s+\d+',
          multiple => true,
        }

        file_line { 'profile':
          path     => '/etc/profile',
          line     => "    umask ${default_umask}",
          match    => '^\s+umask\s+\d+',
          multiple => true,
        }

        file_line { 'login.defs':
          path               => '/etc/login.defs',
          line               => "UMASK           ${default_umask}",
          match              => '^\s*UMASK\s+\d+',
          append_on_no_match => true,
          multiple           => true,
        }

        file_line { 'login.defs-usergroups':
          path               => '/etc/login.defs',
          line               => 'USERGROUPS_ENAB no',
          match              => '^\s*USERGROUPS_ENAB\s*yes',
          append_on_no_match => true,
        }
      }
      'debian': {
        $services = [
          'common-session',
        ]
        file_line { 'login.defs':
          path               => '/etc/login.defs',
          line               => "UMASK           ${default_umask}",
          match              => '^UMASK',
          append_on_no_match => true,
          multiple           => true,
        }

        file_line { 'login.defs-usergroups':
          path               => '/etc/login.defs',
          line               => 'USERGROUPS_ENAB no',
          match              => '^USERGROUPS_ENAB',
          append_on_no_match => true,
        }

        if $facts['os']['name'].downcase() == 'debian' {
          file_line { 'umask-in-bashrc':
            path               => '/etc/bash.bashrc',
            line               => "umask ${default_umask}",
            match              => '^\s*umask',
            append_on_no_match => true,
            multiple           => true,
          }

          file_line { 'profile':
            ensure             => present,
            path               => '/etc/profile',
            line               => "umask ${default_umask}",
            match              => '^\s*umask\s+\d+',
            multiple           => true,
            append_on_no_match => true,
          }
        } else {
          file_line { 'profile':
            ensure            => absent,
            path              => '/etc/profile',
            match             => '^\s*umask\s+\d+',
            multiple          => true,
            match_for_absence => true,
          }
        }
      }
      'suse': {
        $services = []
      }
      default: {
        # noting to be done yet
      }
    }

    file { '/etc/profile.d/set_umask.sh':
      ensure  => file,
      content => epp('cis_security_hardening/rules/common/set_umask.epp', {
          umask => $default_umask,
      }),
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
    }

    $services.each |$srv| {
      $profile = fact('cis_security_hardening.authselect.profile')
      if $profile != undef and $profile != 'none' {
        $pf_path = "/etc/authselect/custom/${profile}"
      } else {
        $pf_path = ''
      }

      $pf_file = "${pf_path}/${srv}"

      if  (
        $facts['os']['name'].downcase() == 'centos' or
        $facts['os']['name'].downcase() == 'almalinux' or
        $facts['os']['name'].downcase() == 'rocky'
      ) and ($facts['os']['release']['major'] > '7' and $facts['os']['release']['major'] < '9') and $pf_path != '' {
        file_line { "umask in ${srv}":
          path               => $pf_file,
          line               => 'session     optional                                     pam_umask.so',
          match              => '^session\s+optional\s+pam_umask.so',
          append_on_no_match => true,
          notify             => Exec['authselect-apply-changes'],
        }
      } else {
        Pam { "pam umask ${srv}":
          ensure  => present,
          service => $srv,
          type    => 'session',
          control => 'optional',
          module  => 'pam_umask.so',
        }
      }
    }
  }
}
