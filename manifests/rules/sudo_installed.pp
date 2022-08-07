# @summary 
#    Ensure sudo is installed (Automated)
#
# sudo allows a permitted user to execute a command as the superuser or another user, as specified by the 
# security policy. The invoking user's real (not effective) user ID is used to determine the user name 
# with which to query the security policy.
# 
# Rationale:
# sudo supports a plugin architecture for security policies and input/output logging. Third parties can 
# develop and distribute their own policy and I/O logging plugins to work seamlessly with the sudo front 
# end. The default security policy is sudoers, which is configured via the file /etc/sudoers.
#
# The security policy determines what privileges, if any, a user has to run sudo. The policy may require 
# that users authenticate themselves with a password or another authentication mechanism. If authentication 
# is required, sudo will exit if the user's password is not entered within a configurable time limit. This 
# limit is policy-specific.
#
# @param enforce
#    Enforce the rule
#
# @ param sudo_pkgs
#    The sudo packages to install.
#
# @param sudo_pkgs
#    Sudo packages to install.
#
# @example
#   class { 'cis_security_hardening::rules::sudo_installed':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sudo_installed (
  Boolean $enforce = false,
  Array $sudo_pkgs = ['sudo']
) {
  if $enforce {
    ensure_packages($sudo_pkgs, {
        ensure => installed,
    })
  }
}
