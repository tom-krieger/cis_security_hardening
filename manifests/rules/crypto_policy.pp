# @summary 
#    Ensure system-wide crypto policy is FUTURE or FIPS 
#
# The system-wide crypto-policies followed by the crypto core components allow consistently deprecating 
# and disabling algorithms system-wide.
# The individual policy levels (DEFAULT, LEGACY, FUTURE, and FIPS) are included in the crypto-policies(7) 
# package.
#
# Rationale:
# If the Legacy system-wide crypto policy is selected, it includes support for TLS 1.0, TLS 1.1, and SSH2 protocols 
# or later. The algorithms DSA, 3DES, and RC4 are allowed, while RSA and Diffie-Hellman parameters are accepted if 
# larger than 1023-bits.
# 
# These legacy protocols and algorithms can make the system vulnerable to attacks, including those listed in RFC 7457.
# 
# FUTURE: Is a conservative security level that is believed to withstand any near-term future attacks. This level does 
# not allow the use of SHA-1 in signature algorithms. The RSA and Diffie-Hellman parameters are accepted if larger than 
# 3071 bits. The level provides at least 128-bit security.
#
# FIPS: Conforms to the FIPS 140-2 requirements. This policy is used internally by the fips-mode-setup(8) tool which can 
# switch the system into the FIPS 140-2 compliance mode. The level provides at least 112-bit security
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param crypto_policy
#    The crypto policy to set in enforce mode.
#
# @param auto_reboot
#    Trigger a reboot if this rule creates a change. Defaults to true.
#
# @example
#   class { 'cis_security_hardening::rules::crypto_policy':
#       enforce => true,
#       crypto_policy = 'FUTURE',
#   }
#
# @api public
class cis_security_hardening::rules::crypto_policy (
  Boolean $enforce                                           = false,
  Enum['FUTURE', 'FIPS', 'LEGACY', 'DEFAULT'] $crypto_policy = 'FUTURE',
  Boolean $auto_reboot                                       = true,
) {
  $notify = $auto_reboot ? {
    true  => Reboot['after_run'],
    false => [],
  }

  if (
    $facts['os']['name'].downcase() == 'centos' or
    $facts['os']['name'].downcase() == 'almalinux' or
    $facts['os']['name'].downcase() == 'rocky'
  ) and $facts['os']['release']['major'] >= '8' {
    $policy = fact('cis_security_hardening.crypto_policy.policy') == undef ? {
      true    => 'undefined',
      default => fact('cis_security_hardening.crypto_policy.policy'),
    }

    $fips_mode = fact('cis_security_hardening.crypto_policy.fips_mode') == undef ? {
      true    => 'undefined',
      default => fact('cis_security_hardening.crypto_policy.fips_mode'),
    }

    if  $enforce and $policy != $crypto_policy {
      exec { "set crypto policy to ${crypto_policy} (current: ${policy})":
        command => "update-crypto-policies --set ${crypto_policy}", #lint:ignore:security_class_or_define_parameter_in_exec 
        path    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
        notify  => $notify,
      }

      if($crypto_policy == 'FUTURE' or $crypto_policy == 'DEFAULT') {
        $enable = 'disable'
      } elsif($crypto_policy == 'FIPS') {
        $enable = 'enable'
      }

      if (
        (($enable == 'enable') and ($fips_mode == 'disabled')) or
        (($enable == 'disable') and ($fips_mode == 'enabled'))
      ) {
        exec { "set FIPS to ${enable}":
          command => "fips-mode-setup --${enable}", #lint:ignore:security_class_or_define_parameter_in_exec
          path    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
          notify  => $notify,
        }
      }
    }
  }
}
