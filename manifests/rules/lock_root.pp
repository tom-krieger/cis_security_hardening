# @summary
#    Ensure root account is locked
#
# The operating system must prevent direct login into the root account.
#
# Rationale:
# To assure individual accountability and prevent unauthorized access, organizational users must be individually 
# identified and authenticated.
#
# A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone 
# does not uniquely identify individual users. Examples of the group authenticator is the UNIX OS "root" user 
# ccount, the Windows "Administrator" account, the "sa" account, or a "helpdesk" account.
#
# For example, the UNIX and Windows operating systems offer a 'switch user' capability allowing users to 
# authenticate with their individual credentials and, when needed, 'switch' to the administrator role. This 
# method provides for unique individual authentication prior to using a group authenticator.
#
# Users (and any processes acting on behalf of users) need to be uniquely identified and authenticated for all 
# accesses other than those accesses explicitly identified and documented by the organization, which outlines 
# specific user actions that can be performed on the operating system without identification or authentication.
#
# Requiring individuals to be authenticated with an individual authenticator prior to using a group authenticator 
# allows for traceability of actions, as well as adding an additional level of protection of the actions that can 
# be taken with group account knowledge.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::lock_root':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::lock_root (
  Boolean $enforce = false,
) {
  if $enforce {
    exec { 'lock root account':
      command => 'passwd -l root',
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => 'test -z "$(passwd -S root | grep \'root L\')"',
    }
  }
}
