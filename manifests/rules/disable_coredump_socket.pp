# @summary
#    Ensure the operating system is not configured to acquire, save, or process core dumps
#
# The operating system must disable acquiring, saving, and processing core dumps. 
#
# Rationale:
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
#
# A core dump includes a memory image taken at the time the operating system terminates an application. The memory image 
# could contain sensitive data and is generally useful only for developers trying to debug problems.
#
# When the kernel invokes systemd-coredumpt to handle a core dump, it runs in privileged mode, and will connect to the 
# socket created by the systemd-coredump.socket unit. This, in turn, will spawn an unprivileged systemd-coredump@.service 
# instance to process the core dump.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::disable_coredump_socket':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_coredump_socket (
  Boolean $enforce = false,
) {
  if $enforce {
    exec { 'mask coredump.socket':
      command => 'systemctl mask systemd-coredump.socket',
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => 'test -z "$(systemctl status systemd-coredump.socket | grep -i "Loaded: masked")"',
      notify  => Exec['systemd-daemon-reload'],
    }
  }
}
