# @summary 
#    Ensure SSH access is limited 
#
# There are several options available to limit which users and group can access the system via SSH. It is recommended that at least 
# one of the following options be leveraged:
#
# AllowUsers
# The AllowUsers variable gives the system administrator the option of allowing specific users to ssh into the system. The list 
# consists of space separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants 
# to restrict user access further by only allowing the allowed users to log in from a particular host, the entry can be specified 
# in the form of user@host. 
#
# AllowGroups
# The AllowGroups variable gives the system administrator the option of allowing specific groups of users to ssh into the system. 
# The list consists of space separated group names. Numeric group IDs are not recognized with this variable. 
#
# DenyUsers
# The DenyUsers variable gives the system administrator the option of denying specific users to ssh into the system. The list 
# consists of space separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants 
# to restrict user access further by specifically denying a user's access from a particular host, the entry can be specified in 
# the form of user@host. 
#
# DenyGroups
# The DenyGroups variable gives the system administrator the option of denying specific groups of users to ssh into the system. 
# The list consists of space separated group names. Numeric group IDs are not recognized with this variable.
#
# Rationale:
# Restricting which users can remotely access the system via SSH will help ensure that only authorized users access the system.
#
# @param enforce
#    Enforce the rule
#
# @param allow_users
#    Array with allowd users to connect by ssh
#
# @param allow_groups
#    Array with unix groups allowed to connect by ssh
#
# @param deny_users
#    Array aith users not allowed to connect by ssh
#
# @param deny_groups
#    Unix groups not allowed to connect by ssh
#
# @example
#   class { 'cis_security_hardening::rules::sshd_limit_access':
#       enforce => true,
#       allow_users => ['user1', 'user2'],
#       deny_users => ['user3'],
#       allow_groups => ['group1','group2'],
#       deny_groups => ['group3'],
#   }
#
# @api private
class cis_security_hardening::rules::sshd_limit_access (
  Boolean $enforce            = false,
  Array[String] $allow_users  = [],
  Array[String] $allow_groups = [],
  Array[String] $deny_users   = [],
  Array[String] $deny_groups  = [],
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true  => '/usr/etc/ssh/sshd_config',
      false => '/etc/ssh/sshd_config',
    }
    unless(empty($allow_users)) {
      $users = join($allow_users, ' ')

      file_line { 'ssh-allow-users':
        ensure => present,
        path   => $path,
        line   => "AllowUsers ${users}",
        match  => '^#?AllowUsers',
        notify => Exec['reload-sshd'],
      }
    }

    unless(empty($allow_groups)) {
      $groups = join($allow_groups, ' ')

      file_line { 'ssh-allow-groups':
        ensure => present,
        path   => $path,
        line   => "AllowGroups ${groups}",
        match  => '^#?AllowGroups',
        notify => Exec['reload-sshd'],
      }
    }

    unless(empty($deny_users)) {
      $deniedusers = join($deny_users, ' ')

      file_line { 'ssh-deny-users':
        ensure => present,
        path   => $path,
        line   => "DenyUsers ${deniedusers}",
        match  => '^#?DenyUsers',
        notify => Exec['reload-sshd'],
      }
    }

    unless(empty($deny_groups)) {
      $deniedgroups = join($deny_groups, ' ')

      file_line { 'ssh-deny-groups':
        ensure => present,
        path   => $path,
        line   => "DenyGroups ${deniedgroups}",
        match  => '^#?DenyGroups',
        notify => Exec['reload-sshd'],
      }
    }
  }
}
