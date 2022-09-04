# @summary
#    Ensure automatic logon via GUI is not allowed
#
# The operating system must not allow an unattended or automatic logon to the system via a graphical user interface.
#
# Rationale:
# Failure to restrict system unattended or automatic logon to the system negatively impacts operating system security.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::gdm_autologin':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::gdm_autologin (
  Boolean $enforce = false,
) {
  if  $enforce {
    $file = $facts['os']['name'].downcase() ? {
      'rocky'     => '/etc/gdm/custom.conf',
      'almalinux' => '/etc/gdm/custom.conf',
      'redhat'    => '/etc/gdm/custom.conf',
      'centos'    => '/etc/gdm/custom.conf',
      default     => '/etc/gdm3/custom.conf',
    }

    ini_setting { 'gdm-autologin':
      ensure  => present,
      path    => $file,
      section => 'daemon',
      setting => 'AutomaticLoginEnable',
      value   => 'false',
    }

    ini_setting { 'gdm-unrestricted':
      ensure  => present,
      path    => $file,
      section => 'daemon',
      setting => 'TimedLoginEnable',
      value   => 'false',
    }
  }
}
