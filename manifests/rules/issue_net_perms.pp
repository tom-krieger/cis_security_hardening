# @summary 
#    Ensure permissions on /etc/issue.net are configured 
#
# The contents of the /etc/issue.net file are displayed to users prior to login for 
# remote connections from configured services.
#
# Rationale:
# If the /etc/issue.net file does not have the correct ownership it could be modified 
# by unauthorized users with incorrect or misleading information.
#
# @param enforce
#    Enforce the rule
#
# @param content
#    The content to write into the file
#
# @example
#   class { 'cis_security_hardening::rules::issue_net_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::issue_net_perms (
  Boolean $enforce           = false,
  Optional[String] $content  = undef,
) {
  if $enforce {
    $data = $content ? {
      undef   => {
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
    ensure_resource('file', '/etc/issue.net', $data)
  }
}
