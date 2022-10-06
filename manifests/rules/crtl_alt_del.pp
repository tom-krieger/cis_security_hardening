  # @summary
#    Ensure the Ctrl-Alt-Delete key sequence is disabled
#
# The operating system must disable the x86 Ctrl-Alt-Delete key sequence.
#
# Rationale:
# A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally 
# pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of 
# availability of systems due to unintentional reboot.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::crtl_alt_del':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::crtl_alt_del (
  Boolean $enforce = false,
) {
  if $enforce {
    exec { 'mask ctrl-alt-del.target':
      command => 'systemctl mask ctrl-alt-del.target',
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => 'test -z "$(systemctl status ctrl-alt-del.target | grep -i "Loaded: masked")"',
      notify  => Exec['systemd-daemon-reload'],
    }

    if $facts['os']['name'].downcase() == 'redhat' and $facts['os']['release']['major'] >= '8' {
      file_line { 'ctrl-alt-del-burst':
        ensure             => present,
        path               => '/etc/systemd/system.conf',
        match              => '^CtrlAltDelBurstAction=',
        line               => 'CtrlAltDelBurstAction=none',
        append_on_no_match => true,
        notify             => Exec['systemd-daemon-reload'],
      }
    }
  }
}
