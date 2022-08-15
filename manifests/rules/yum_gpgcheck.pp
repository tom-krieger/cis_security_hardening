# @summary 
#    Ensure gpgcheck is globally activated (Scored)
#
# The gpgcheck option, found in the main section of the /etc/yum.conf and individual /etc/yum/repos.d/* 
# files determines if an RPM package's signature is checked prior to its installation.
#
# Rationale:
# It is important to ensure that an RPM's package signature is always checked prior to installation to 
# ensure that the software is obtained from a trusted source.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::yum_gpgcheck':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::yum_gpgcheck (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'yum_gpgcheck':
      ensure => present,
      path   => '/etc/yum.conf',
      line   => 'gpgcheck=1',
      match  => '^gpgcheck',
    }

    if $facts['osfamily'].downcase() == 'redhat' and $facts['operatingsystemmajrelease'] >= '8' {
      file_line { 'yum_gpgcheck dns':
        ensure => present,
        path   => '/etc/dnf/dnf.conf',
        line   => 'gpgcheck=1',
        match  => '^gpgcheck',
      }
    }
  }
}
