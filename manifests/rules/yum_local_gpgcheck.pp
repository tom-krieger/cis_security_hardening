# @summary
#    Ensure software packages have been digitally signed by a Certificate Authority
#
# The operating system must prevent the installation of software, patches, service packs, device drivers, 
# or operating system components of local packages without verification they have been digitally signed using 
# a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.
#
# Rationale:
# Changes to any software components can have significant effects on the overall security of the operating system. 
# This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.
#
# Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate 
# recognized and approved by the organization.
#
# Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade 
# received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted 
# vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the 
# software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to 
# verify the software must be from an approved CA.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::yum_local_gpgcheck':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::yum_local_gpgcheck (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'yum_localpkg_gpgcheck':
      ensure             => present,
      path               => '/etc/yum.conf',
      line               => 'localpkg_gpgcheck=1',
      match              => '^localpkg_gpgcheck',
      append_on_no_match => true,
    }

    if $facts['os']['release']['major'] >= '8' {
      file_line { 'dnf_localpgk_gpgcheck':
        ensure             => present,
        path               => '/etc/dnf/dnf.conf',
        line               => 'localpkg_gpgcheck=1',
        match              => '^localpkg_gpgcheck',
        append_on_no_match => true,
      }
    }
  }
}
