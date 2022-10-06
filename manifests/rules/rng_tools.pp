# @summary
#    Ensure the system has the packages required to enable the hardware random number generator entropy gatherer service
#
# The operating system must have the packages required to use the hardware random number generator entropy gatherer service.
#
# Rationale:
# The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers 
# that are impossible to predict. Entropy in computer security is associated with the unpredictability of a source of randomness. 
# The random source with high entropy tends to achieve a uniform distribution of random values. Random number generators are one 
# of the most important building blocks of cryptosystems.
#
# The rngd service feeds random data from hardware device to kernel random device. Quality (non-predictable) random number generation 
# is important for several security functions (i.e., ciphers).
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::rng_tools':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::rng_tools (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['rng-tools'], {
        ensure => installed,
    })
  }
}
