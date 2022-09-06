# @summary 
#    Ensure the SSH server uses strong entropy
#
# Administrators must ensure the SSH server uses strong entropy. 
#
# Rationale:
# The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers 
# that are impossible to predict. Entropy in computer security is associated with the unpredictability of a source of randomness. 
# The random source with high entropy tends to achieve a uniform distribution of random values.
#
# Random number generators are one of the most important building blocks of cryptosystems.
#
# The SSH implementation in RHEL 8 operating systems uses the OPENSSL library, which does not use high-entropy sources by default. 
# By using the "SSH_USE_STRONG_RNG" environment variable the OPENSSL random generator is reseeded from "/dev/random".
#
# This setting is not recommended on computers without the hardware random generator because insufficient entropy causes the 
# connection to be blocked until enough entropy is available.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_strong_rng':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_strong_rng (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd_strong_rng':
      ensure             => present,
      path               => $path,
      match              => '^SSH_USE_STRONG_RNG=',
      line               => 'SSH_USE_STRONG_RNG=32',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}
