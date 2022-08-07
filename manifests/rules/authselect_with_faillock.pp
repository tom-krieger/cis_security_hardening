 # @summary 
#    Ensure authselect includes with-faillock (Scored)
#
# The pam_faillock.so module maintains a list of failed authentication attempts per user during a specified 
# interval and locks the account in case there were more than deny consecutive failed authentications. It 
# stores the failure records into per-user files in the tally directory.
#
# Rationale:
# Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password 
# attacks against your systems.
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::authselect_with_faillock':   
#             enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::authselect_with_faillock (
  Boolean $enforce = false,
) {
  if $enforce {
    $current_options = fact('cis_security_hardening.authselect.current_options')
    $profile = fact('cis_security_hardening.authselect.profile')

    if (!('with-faillock' in $current_options)) and ($profile != 'none') {
      exec { 'select authselect with-faillock':
        command => "authselect select custom/${profile} with-sudo with-faillock without-nullok -f",
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        onlyif  => ["test -d /etc/authselect/custom/${profile}",
        "test -z \"$(authselect current | grep 'with-faillock')\""],
        returns => [0, 1],
      }
    }
  }
}
