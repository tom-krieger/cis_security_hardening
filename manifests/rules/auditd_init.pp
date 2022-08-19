# @summary 
#    Initialize auditd rules file
#
# Write inital rules for auditd
#
# @param enforce
#    Enforce the rule
#
# @param buffer_size
#    Value for Buffer size in rules file header.
#
# @param rules_file
#    File to write the rules into.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_init':
#       enforce => true,
#       buffer_size => 8192,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_init (
  Boolean $enforce                 = false,
  Integer $buffer_size             = 8192,
  Stdlib::Absolutepath $rules_file = '/etc/audit/rules.d/cis_security_hardening.rules',
) {
  if $enforce {
    concat { $rules_file:
      ensure         => present,
      owner          => 'root',
      group          => 'root',
      mode           => '0640',
      ensure_newline => true,
      notify         => [Exec['reload auditd rules'], Reboot['after_run']],
    }

    concat::fragment { 'auditd init delete rules':
      order   => '01',
      target  => $rules_file,
      content => '-D',
    }

    concat::fragment { 'auditd init set buffer':
      order   => '02',
      target  => $rules_file,
      content => "-b ${buffer_size}",
    }
  }

  $cmd = "auditctl -R ${rules_file}"
  exec { 'reload auditd rules':
    refreshonly => true,
    command     => $cmd,
    path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
  }
}
