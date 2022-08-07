# @summary 
#    Ensure gpgcheck is globally activated (Automated)
#
# The gpgcheck option, found in the main section of the /etc/zypp/zypp.conf and individual 
# /etc/zypp/repos.d/*.repo files determine if an RPM package's signature is checked prior 
# to its installation.
#
# Rationale:
# It is important to ensure that an RPM's package signature is always checked prior to 
# installation to ensure that the software is obtained from a trusted source.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::zypper_gpgcheck':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::zypper_gpgcheck (
  Boolean $enforce = false,
) {
  if $enforce {
    ini_setting { 'enable ggpcheck':
      ensure  => present,
      path    => '/etc/zypp/zypp.conf',
      section => 'main',
      setting => 'gpgcheck',
      value   => '1',
    }
  }
}
