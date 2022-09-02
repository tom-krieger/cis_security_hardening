# @summary 
#    Ensure FIPS mode is enabled
#
# The operating system must implement NIST FIPS-validated cryptography to protect classified information and for the following: 
# to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality 
# and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, 
# and standards.
#
# Rationale:
# Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating 
# system must implement cryptographic modules adhering to the higher standards approved by the federal government since this 
# provides assurance they have been tested and validated.
# Satisfies: SRG-OS-000396-GPOS-00176, SRG-OS-000478-GPOS-00223
#
# Impact:
# Enabling a FIPS mode on a pre-existing system involves a number of modifications to the Ubuntu operating system. Refer 
# to the Ubuntu Server 18.04 FIPS 140-2 security policy document for instructions.
# Note: A subscription to the "Ubuntu Advantage" plan is required in order to obtain the FIPS Kernel cryptographic modules 
# and enable FIPS.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::fips_bootloader':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::fips_bootloader (
  Boolean $enforce = false,
) {
  if $enforce and ($facts['osfamily'].downcase() == 'debian' or $facts['osfamily'].downcase() == 'suse') {
    kernel_parameter { 'fips':
      value  => '1',
      notify => Exec['fips-grub-config'],
    }

    case $facts['osfamily'].downcase() {
      'debian': {
        $cmd = 'update-grub'
      }
      'suse': {
        $cmd = 'grub2-mkconfig -o /boot/grub2/grub.cfg'
      }
      default: {
        $cmd = ''
      }
    }

    if ! empty($cmd) {
      exec { 'fips-grub-config':
        command     => $cmd,
        path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        refreshonly => true,
      }
    }
  }
}
