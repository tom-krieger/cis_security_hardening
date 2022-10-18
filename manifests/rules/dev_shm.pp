# @summary 
#    Ensure /dev/shm is configured 
#
# /dev/shm is a traditional shared memory concept. One program will create a memory portion, which other processes 
# (if permitted) can access. If /dev/shm is not configured, tmpfs will be mounted to /dev/shm by systemd.
#
# Rationale:
# Any user can upload and execute files inside the /dev/shm similar to the /tmp partition. Configuring /dev/shm allows an administrator 
# to set the noexec option on the mount, making /dev/shm useless for an attacker to install executable code. It would also prevent an 
# attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the 
# hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security 
# vulnerability, the attacker could continue to exploit the known flaw.
#
# @param enforce
#    Enforce the rule
#
# @param size
#    Size in GB
#
# @example
#   class { 'cis_security_hardening::rules::dev_shm':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::dev_shm (
  Boolean $enforce = false,
  Integer $size    = 0,
) {
  if $enforce {
    if $size == 0 {
      $options = 'defaults,nodev,nosuid,noexec,seclabel'
    } else {
      $options = "defaults,size=${size}G,nodev,nosuid,noexec,seclabel"
    }

    $line = "tmpfs   /dev/shm        tmpfs   ${options}   0 0"
    file_line { 'add /dev/shm to fstab':
      ensure             => present,
      path               => '/etc/fstab',
      match              => "^tmpfs\\s* /dev/shm",
      line               => $line,
      append_on_no_match => true,
    }
  }
}
