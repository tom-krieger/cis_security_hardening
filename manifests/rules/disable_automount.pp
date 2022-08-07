# @summary 
#    Disable Automounting (Automated)
#
# autofs allows automatic mounting of devices, typically including CD/DVDs and USB drives.
#
# Rationale:
# With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents 
# available in system even if they lacked permissions to mount it themselves.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::disable_automount':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_automount (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_resource('service', 'autofs', {
        ensure => stopped,
        enable => false,
    })
  }
}
