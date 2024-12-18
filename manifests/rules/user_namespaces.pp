# @summary
#    Ensure the operating system disables the use of user namespaces
#
# The operating system must disable the use of user namespaces. 
#
# Rationale:
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
#
# User namespaces are used primarily for Linux container. The value 0 disallows the use of user namespaces. When containers 
# are not in use, namespaces should be disallowed. When containers are deployed on a system, the value should be set to a 
# large non-zero value. The default value is 7182.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::user_namespaces':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::user_namespaces (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'user.max_user_namespaces':
        ensure => present,
        value  => 0,
        notify => Exec['reload-sysctl-system'],
    }
  }
}
