# @summary 
#    Ensure SSH AllowTcpForwarding is disabled (Automated)
#
# SSH port forwarding is a mechanism in SSH for tunneling application ports from the client to the server, 
# or servers to clients. It can be used for adding encryption to legacy applications, going through firewalls, 
# and some system administrators and IT professionals use it for opening backdoors into the internal network 
# from their home machines
#
# Rationale:
# Leaving port forwarding enabled can expose the organization to security risks and backdoors.
# SSH connections are protected with strong encryption. This makes their contents invisible to most deployed 
#network monitoring and traffic filtering solutions. This invisibility carries considerable risk potential if 
# it is used for malicious purposes such as data exfiltration. Cybercriminals or malware could exploit SSH to 
# hide their unauthorized communications, or to exfiltrate stolen data from the target network
#
# @param enforce
#    Enforce the rule 
#
# @example
#   class { 'cis_security_hardening::rules::sshd_tcp_forwarding':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_tcp_forwarding (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-tcp-forwarding':
      ensure             => present,
      path               => $path,
      line               => 'AllowTcpForwarding no',
      match              => '^AllowTcpForwarding.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}
