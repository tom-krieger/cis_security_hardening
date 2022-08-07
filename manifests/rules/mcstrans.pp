# @summary 
#    Ensure the MCS Translation Service (mcstrans) is not installed (Automated)
#
# The mcstransd daemon provides category label information to client processes requesting 
# information. The label translations are defined in /etc/selinux/targeted/setrans.conf
#
# Rationale:
# Since this service is not used very often, remove it to reduce the amount of potentially 
# vulnerable code running on the system.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class cis_security_hardening::rules::mcstrans {
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::mcstrans (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['osfamily'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }
    ensure_packages(['mcstrans'], {
        ensure => $ensure,
    })
  }
}
