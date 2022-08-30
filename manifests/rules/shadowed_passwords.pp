# @summary 
#    Ensure accounts in /etc/passwd use shadowed passwords 
#
# Local accounts can uses shadowed passwords. With shadowed passwords, The passwords are saved in shadow 
# password file, /etc/shadow, encrypted by a salted one-way hash. Accounts with a shadowed password have 
# an x in the second field in /etc/passwd.
#
# Rationale:
# The /etc/passwd file also contains information like user ID's and group ID's that are used by many system 
# programs. Therefore, the /etc/passwd file must remain world readable. In spite of encoding the password 
# with a randomly-generated one-way hash function, an attacker could still break the system if they got access 
# to the /etc/passwd file. This can be mitigated by using shadowed passwords, thus moving the passwords in the 
# /etc/passwd file to /etc/shadow. The /etc/shadow file is set so only root will be able to read and write. This 
# helps mitigate the risk of an attacker gaining access to the encoded passwords with which to perform a dictionary 
# attack.
#
# Notes:
# * All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user.
# * A user account with an empty second field in /etc/passwd allows the account to be logged into by providing 
#   only the username.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::shadowed_passwords':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::shadowed_passwords (
  Boolean $enforce = false,
) {
  if $enforce {
    exec { 'enforce shadowed passwords':
      command => 'sed -e \'s/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/\' -i /etc/passwd',
      path    => ['/bin', '/usr/bin'],
      unless  => 'test -z "$(awk -F: \'($2 != "x" ) { print $1 " is not set to shadowed passwords "}\' /etc/passwd)"',
    }
  }
}
