# @summary 
#    Ensure mail transfer agent is configured for local-only mode 
#
# Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming mail 
# and transfer the messages to the appropriate user or mail server. If the system is not intended 
# to be a mail server, it is recommended that the MTA be configured to only process local mail.
#
# Rationale:
# The software for all Mail Transfer Agents is complex and most have a long history of security issues. 
# While it is important to ensure that the system can process local mail messages, it is not necessary to 
# have the MTA's daemon listening on a port unless the server is intended to be a mail server that receives 
# and processes mail from other systems.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::mta_local':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::mta_local (
  Boolean $enforce = false,
) {
  if  $enforce and
  fact('cis_security_hardening.postfix') == 'yes' {
    file_line { 'mta-loca-config':
      path     => '/etc/postfix/main.cf',
      line     => 'inet_interfaces = loopback-only',
      match    => 'inet_interfaces\s*=',
      multiple => true,
      notify   => Exec['restart postfix'],
    }

    exec { 'restart postfix':
      command     => 'systemctl restart postfix',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
  }
}
