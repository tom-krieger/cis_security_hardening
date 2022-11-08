# @summary 
#    Ensure only strong Key Exchange algorithms are used 
#
# Key exchange is any method in cryptography by which cryptographic keys are exchanged between two parties, allowing 
# use of a cryptographic algorithm. If the sender and receiver wish to exchange encrypted messages, each must be 
# equipped to encrypt messages to be sent and decrypt messages received
#
# Rationale:
# Key exchange methods that are considered weak should be removed. A key exchange method may be weak because too few 
# bits are used, or the hashing algorithm is considered too weak. Using weak algorithms could expose connections to 
# man-in-the-middle attacks.
#
# @param enforce
#    Enforce the rule 
#
# @param kexs 
#    Key exchange methods to add to config
#
# @example
#   class { 'cis_security_hardening::rules::sshd_kex':
#       enforce => true,
#       kexs => ['a','b'],
#   }
#
# @api private
class cis_security_hardening::rules::sshd_kex (
  Boolean $enforce  = false,
  Array $kexs       = [],
) {
  if $enforce {
    if (!empty($kexs)) {
      $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
        true    => '/usr/etc/ssh/sshd_config',
        default => '/etc/ssh/sshd_config',
      }
      $kexlist = $kexs.join(',')
      file_line { 'sshd-kexs':
        ensure => present,
        path   => $path,
        line   => "Kexalgorithms ${kexlist}",
        match  => '^#?Kexalgorithms.*',
        notify => Exec['reload-sshd'],
      }
    }
  }
}
