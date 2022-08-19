# @summary 
#    Ensure default user shell timeout is configured 
#
# The default TMOUT determines the shell timeout for users. The TMOUT value is measured in seconds.
#
# Rationale:
# Having no timeout value associated with a shell could allow an unauthorized user access to another user's 
# shell session (e.g. user walks away from their computer and doesn't lock the screen). Setting a timeout 
# value at least reduces the risk of this happening.
#
# @param enforce
#    Enforce the rule
#
# @param default_timeout
#    Default timeout to set
#
# @example
#   class cis_security_hardening::rules::timeout_setting {
#       enforce => true,
#       default_timeout => 900,
#   }
#
# @api private
class cis_security_hardening::rules::timeout_setting (
  Boolean $enforce         = false,
  Integer $default_timeout = 900,
) {
  if $enforce {
    file { '/etc/profile.d/shell_timeout.sh':
      ensure  => file,
      content => epp('cis_security_hardening/rules/common/shell_timeout.epp', {
          default_timeout => $default_timeout,
          os              => $facts['operatingsystem'].downcase(),
      }),
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
    }

    if $facts['operatingsystem'].downcase() == 'debian' {
      file { '/etc/profile':
        ensure  => file,
        content => epp('cis_security_hardening/rules/common/profile.debian.epp', {
            default_timeout => $default_timeout,
        }),
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
      }

      file { '/etc/bash.bashrc':
        ensure  => file,
        content => epp('cis_security_hardening/rules/common/bash.bashrc.debian.epp', {
            default_timeout => $default_timeout,
        }),
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
      }
    }
  }
}
