# @summary
#    Ensure SCTP is disabled
#
# The Stream Control Transmission Protocol (SCTP) is a transport layer protocol used to support
# message oriented communication, with several streams of messages in one connection. It serves
# a similar function as TCP and UDP, incorporating features of both. It is message-oriented like
# UDP, and ensures reliable in-sequence transport of messages with congestion control like TCP.
#
# Rationale:
# If the protocol is not being used, it is recommended that kernel module not be loaded, disabling
# the service to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::disable_sctp':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_sctp (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'debian': {
        if $facts['os']['release']['major'] > '10' {
          $command = '/bin/false'
          kmod::blacklist { 'sctp': }
        } else {
          $command = '/bin/true'
        }
      }
      'ubuntu': {
        if $facts['os']['release']['major'] >= '20' {
          $command = '/bin/false'
          kmod::blacklist { 'sctp': }
        } else {
          $command = '/bin/true'
        }
      }
      default: {
        $command = '/bin/true'
      }
    }

    kmod::install { 'sctp':
      command => $command,
    }
  }
}
