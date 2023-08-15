# @summary 
#    Ensure access to the su command is restricted 
#
# The su command allows a user to run a command or shell as another user. The program has been superseded 
# by sudo , which allows for more granular control over privileged access. Normally, the su command can be 
# executed by any user. By uncommenting the pam_wheel.so statement in /etc/pam.d/su , the su command will 
# only allow users in the wheel group to execute su.
#
# Rationale:
# Restricting the use of su , and using sudo in its place, provides system administrators better control of 
# the escalation of user privileges to execute privileged commands. The sudo utility also provides a better 
# logging and audit mechanism, as it can log each command executed via sudo , whereas su can only record that 
# a user executed the su program.
#
# @param enforce
#    Enforce the rule
#
# @param wheel_users
#    Users to be added to the wheel group.
#
# @param sudo_group
#    Group for sudo
#
# @example
#   class { 'cis_security_hardening::rules::restrict_su':
#       enforce => true,
#       wheel_users => ['root'],
#   }
#
# @api private
class cis_security_hardening::rules::restrict_su (
  Boolean $enforce                         = false,
  Array $wheel_users                       = ['root'],
  Cis_security_hardening::Word $sudo_group = 'wheel',
) {
  if($enforce) {
    if $facts['os']['family'].downcase() == 'redhat'and $facts['os']['release']['major'] >= '9' {
      $args = ['use_uid']
    } else {
      $args = ['use_uid',"group=${sudo_group}"]
    }
    Pam { 'pam-su-restrict':
      ensure    => present,
      service   => 'su',
      type      => 'auth',
      control   => 'required',
      module    => 'pam_wheel.so',
      arguments => $args,
    }

    group { $sudo_group:
      ensure => present,
    }

    $wheel_users.each | $user | {
      unless $sudo_group =~ /^[0-9a-zA-Z\_]+$/ {
        fail("Illegal sudo group: ${sudo_group}")
      }
      unless $user =~ /^[0-9a-zA-Z\_]+$/ {
        fail("Illegal sudo group: ${user}")
      }

      exec { "${user}_wheel":
        command => "usermod -G ${sudo_group} ${user}",  #lint:ignore:security_class_or_define_parameter_in_exec
        unless  => "grep ${sudo_group} /etc/group | grep ${user}",
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      }
    }
  }
}
