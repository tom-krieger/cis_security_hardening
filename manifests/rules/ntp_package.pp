# @summary 
#    Install ntp package
#
# Install packages for chrony or ntp.
#
# @param enforce
#    Enforce the rule
#
# @param pkg
#    The ntp package to install
#
# class { 'cis_security_hardening::rules::ntp_package':
#   enforce => true,
#   pkg => 'ntp',
#   }
#
# @api private
class cis_security_hardening::rules::ntp_package (
  Boolean $enforce           = false,
  Enum['ntp', 'chrony'] $pkg = 'ntp',
) {
  if $enforce {
    ensure_packages($pkg, {
        ensure => installed,
    })
  }
}
