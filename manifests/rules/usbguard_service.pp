# @summary 
#    Ensure the operating system has enabled the use of the USBGuard
#
# The operating system must enable USBGuard.
#
# Rationale:
# Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious 
# activity.
#
# Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.
#
# A new feature that RHEL 8 operating systems provide is the USBGuard software framework. The USBguard-daemon is the main 
# component of the USBGuard software framework. It runs as a service in the background and enforces the USB device authorization 
# policy for all USB devices. The policy is defined by a set of rules using a rule language described in the "usbguard-rules.conf" 
# file. The policy and the authorization state of USB devices can be modified during runtime using the USBGuard tool.
#
# The System Administrator (SA) must work with the site Information System Security Officer (ISSO) to determine a list of 
# authorized peripherals and establish rules within the USBGuard software framework to allow only authorized devices.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::usbguard_service':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::usbguard_service (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_resource('service', 'usbguard', {
        ensure => running,
        enable => true,
    })
  }
}
