# @summary 
#    Ensure only approved MAC algorithms are used 
#
# This variable limits the types of MAC algorithms that SSH can use during communication.
#
# Rationale:
# MD5 and 96-bit MAC algorithms are considered weak and have been shown to increase exploitability in SSH downgrade attacks. 
# Weak algorithms continue to have a great deal of attention as a weak spot that can be exploited with expanded computing 
# power. An attacker that breaks the algorithm could take advantage of a MiTM position to decrypt the SSH tunnel and capture 
# credentials and information.
#
# @param enforce
#    Enforce the rule 
#
# @param macs
#    MAC algorithms to add to config
#
# @example
#   class { 'cis_security_hardening::rules::sshd_macs':
#       enforce => true,
#       macs => ['a','b'],
#   }
#
# @api private
class cis_security_hardening::rules::sshd_macs (
  Boolean $enforce  = false,
  Array $macs       = [],
) {
  if $enforce {
    if (!empty($macs)) {
      $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
        true    => '/usr/etc/ssh/sshd_config',
        default => '/etc/ssh/sshd_config',
      }
      $maclist = $macs.join(',')
      file_line { 'sshd-macs':
        ensure => present,
        path   => $path,
        line   => "MACs ${maclist}",
        match  => '^#?MACs.*',
        notify => Exec['reload-sshd'],
      }
    }
  }
}
