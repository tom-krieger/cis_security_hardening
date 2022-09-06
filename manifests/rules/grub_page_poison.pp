# @summary
#    Ensure GRUB 2 is configured to enable page poisoning to mitigate use-after-free vulnerabilities
#
# The operating system must clear the page allocator to prevent use-after-free attacks. 
#
# Rationale:
# Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations 
# that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address 
# space layout randomization. Data execution prevention safeguards can be either hardware- enforced or software-enforced with hardware 
# providing the greater strength of mechanism.
#
# Poisoning writes an arbitrary value to freed pages, so any modification or reference to that page after being freed or before being 
# initialized will be detected and prevented. This prevents many types of use-after-free vulnerabilities at little performance cost. 
# Also prevents leak of data and detection of corrupted memory.
#
# Satisfies: SRG-OS-000134-GPOS-00068, SRG-OS-000433-GPOS-00192
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::grub_page_poison':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::grub_page_poison (
  Boolean $enforce = false,
) {
  if $enforce {
    kernel_parameter { 'page_poison':
      value  => '1',
      notify => Exec['grub2-mkconfig'],
    }
  }
}
