# @summary
#    Ensure NIST FIPS-validated cryptography is configured
#
# The operating system must implement NIST FIPS-validated cryptography for the following:
# * provision digital signatures
# * generate cryptographic hashes
# * protect data requiring data-at-rest protections in accordance with applicable federal
# laws, Executive Orders, directives, policies, regulations, and standards.
#
# Rationale:
# Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. 
# The operating system must implement cryptographic modules adhering to the higher standards approved by the 
# federal government since this provides assurance they have been tested and validated.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::dracut_fips':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::dracut_fips (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['dracut-fips'], {
        ensure => installed,
        notify => Exec['recreate initramfs'],
    })

    exec { 'recreate initramfs':
      command     => 'dracut -f',
      path        => ['/sin','/usr/sbin','/bin','/usr/bin'],
      refreshonly => true,
    }
  }
}
