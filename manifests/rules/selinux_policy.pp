# @summary 
#    Ensure SELinux policy is configured 
#
# Configure SELinux to meet or exceed the default targeted policy, which constrains daemons and system software only.
#
# Rationale:
# Security configuration requirements vary from site to site. Some sites may mandate a policy that is 
# stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that 
# at least the default recommendations are met.
#
# @param enforce
#    Enforce the rule
#
# @param selinux_policy
#    SELinux policy
#
# @param auto_reboot
#    Trigger a reboot if this rule creates a change. Defaults to true.
#
# @example
#   class { 'cis_security_hardening::rules::selinux_policy':
#       enforce => true,
#       selinux_policy => 'targeted',
#   }
#
# @api public
class cis_security_hardening::rules::selinux_policy (
  Boolean $enforce       = false,
  String $selinux_policy = 'targeted',
  Boolean $auto_reboot   = true,
) {
  if $enforce {
    $notify = $auto_reboot ? {
      true  => Reboot['after_run'],
      false => [],
    }

    ensure_resource('file', '/etc/selinux/config', {
        ensure => present,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
        notify => $notify
    })

    file_line { 'selinux_targeted':
      path   => '/etc/selinux/config',
      line   => "SELINUXTYPE=${selinux_policy}",
      match  => '^SELINUXTYPE=',
      notify => $notify,
    }
  }
}
