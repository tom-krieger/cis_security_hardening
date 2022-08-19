# @summary 
#   Ensure /tmp is configured 
#
# The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.
#
# Rationale:
# Making /tmp its own file system allows an administrator to set the noexec option on the mount, making /tmp useless 
# for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a 
# system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken 
# and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, 
# the attacker could continue to exploit the known flaw.
#
# This can be accomplished by either mounting tmpfs to /tmp, or creating a separate partition for /tmp.
#
# @param enforce
#    Enforce the rule
#
# @param size
#    size of the /tmp filesyetem in GB
#
# @param enable
#    enable systemd service
#
# @example
#   class { 'cis_security_hardening::rules::tmp_filesystem':
#       enforce => true,
#       size => '2G',
#       enable => true,
#   }
#
# @api private
class cis_security_hardening::rules::tmp_filesystem (
  Boolean $enforce = false,
  Integer $size    = 0,
  Boolean $enable  = true,
) {
  if $enforce {
    $file = '/etc/systemd/system/tmp.mount'
    case $facts['operatingsystem'].downcase() {
      'ubuntu': {
        $epp = 'tmp.mount.ubuntu.epp'
      }
      'debian': {
        $epp = 'tmp.mount.debian.epp'
      }
      'sles': {
        $epp = 'tmp.mount.sles.epp'
      }
      default: {
        $epp = 'tmp.mount.epp'
      }
    }

    file { $file:
      ensure  => file,
      content => epp("cis_security_hardening/rules/common/${epp}", {
          size => $size,
      }),
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      notify  => Exec['systemd-daemon-reload'],
    }

    ensure_resource('service', 'tmp.mount', {
        ensure => running,
        enable => $enable,
    })
  }
}
