# @summary 
#    Ensure permissions on /etc/issue are configured 
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
# @param file
#    The file to be used as content. Give a Puppet file resource.
#
# @example
#   class { 'cis_security_hardening::rules::issue_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::issue_perms (
  Boolean $enforce           = false,
  Optional[String] $content  = undef,
  Optional[String] $file     = undef,
) {
  if $enforce {
    $issue_link = fact('cis_security_hardening.etc_issue_link')

    if $file == undef {
      $data = $content ? {
        undef => {
          ensure  => present,
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
        },
        default => {
          ensure  => present,
          content => $content,
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
        },
      }
    } else {
      $data = {
        ensure  => present,
        source  => $file,
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
      }
    }

    unless  $facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12' and $issue_link {
      ensure_resource('file', '/etc/issue', $data)
    }
  }
}
