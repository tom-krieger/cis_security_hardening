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
# @param auto_reboot
#    Trigger a reboot if this rule creates a change. Defaults to true.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_init':
#       enforce => true,
#       buffer_size => 8192,
#   }
#
# @api public
class cis_security_hardening::rules::auditd_init (
  Boolean $enforce                 = false,
  Integer $buffer_size             = 8192,
  Stdlib::Absolutepath $rules_file = '/etc/audit/rules.d/cis_security_hardening.rules',
  Boolean $auto_reboot             = true,
) {
  if $enforce {
    $notify = $auto_reboot ? {
      true  => [Exec['reload auditd rules'], Reboot['after_run']],
      false => Exec['reload auditd rules'],
    }

    concat { $rules_file:
      ensure         => present,
      owner          => 'root',
      group          => 'root',
      mode           => '0640',
      ensure_newline => true,
      notify         => $notify,
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

  exec { 'reload auditd rules':
    refreshonly => true,
    command     => "auditctl -R ${rules_file}", #lint:ignore:security_class_or_define_parameter_in_exec
    path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
  }
}
