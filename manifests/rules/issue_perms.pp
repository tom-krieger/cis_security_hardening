# @summary 
#    Ensure permissions on /etc/issue are configured (Automated)
#
# The contents of the /etc/issue file are displayed to users prior to login for local terminals.
#
# Rationale:
# If the /etc/issue file does not have the correct ownership it could be modified by unauthorized 
# users with incorrect or misleading information.
#
# @param enforce
#    Enforce the rule
#
# @param content
#    The content to write into the file
#
# @example
#   class { 'cis_security_hardening::rules::issue_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::issue_perms (
  Boolean $enforce = false,
  String $content  = '',
) {
  if $enforce {
    unless  $facts['operatingsystem'] == 'SLES' and
    $facts['operatingsystemmajrelease'] == '12' and
    has_key($facts, 'cis_security_hardening') and
    has_key($facts['cis_security_hardening'], 'etc_issue_link') and
    $facts['cis_security_hardening']['etc_issue_link'] {
      ensure_resource('file', '/etc/issue', {
          ensure  => present,
          content => $content,
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
      })
    }
  }
}
