# @summary 
#    Ensure message of the day is configured properly 
#
# The contents of the /etc/motd file are displayed to users after login and function as a message of the day 
# for authenticated users. Unix-based systems have typically displayed information about the OS release and 
# patch level upon logging in to the system. This information can be useful to developers who are developing 
# software for a particular OS platform. If mingetty(8) supports the following options, they display operating 
# system information: \m - machine architecture \r - operating system release \s - operating system 
# name \v - operating system version
#
# Rationale:
# Warning messages inform users who are attempting to login to the system of their legal status regarding the 
# system and must include the name of the organization that owns the system and any monitoring policies that are 
# in place. Displaying OS and patch level information in login banners also has the side effect of providing 
# detailed system information to attackers attempting to target specific exploits of a system. Authorized users 
# can easily get this information by running the " uname -a " command once they have logged in.
#
# @param enforce
#    Enforce the rule
#
# @param content
#    The content to write into the file
#
# @example
#   class { 'cis_security_hardening::rules::motd_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::motd_perms (
  Boolean $enforce          = false,
  Optional[String] $content = undef,
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
    ensure_resource('file', '/etc/motd', $data)
  }
}
