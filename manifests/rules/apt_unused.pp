# @summary
#    Ensure the Advance Package Tool removes all software components after updated versions have been installed
#
# The Ubuntu operating system must be configured so that Advance Package Tool (APT) removes all software components 
# after updated versions have been installed.
#
# Rationale:
# Previous versions of software components that are not removed from the information system after updates have been 
# installed may be exploited by adversaries. Some information technology products may remove older versions of 
# software automatically from the information system.
#
# @param enforce
#    Enforce autoremove
# @param files
#    List of files to check
#
# @example
#   class { 'cis_security_hardening::rules::apt_unused':
#     ensure => true,
#   }
#
# @api private
class cis_security_hardening::rules::apt_unused (
  Boolean $enforce = false,
  Array $files = ['/etc/apt/apt.conf.d/50unattended-upgrades']
) {
  if $enforce {
    $files.each |$file| {
      file { $file:
        ensure => file,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
      }

      file_line { 'add Unattended-Upgrade::Remove-Unused-Dependencies':
        ensure             => present,
        path               => $file,
        match              => '^Unattended-Upgrade::Remove-Unused-Dependencies',
        line               => 'Unattended-Upgrade::Remove-Unused-Dependencies "true";',
        append_on_no_match => true,
      }

      file_line { 'add Unattended-Upgrade::Remove-Unused-Kernel-Packages':
        ensure             => present,
        path               => $file,
        match              => '^Unattended-Upgrade::Remove-Unused-Kernel-Packages',
        line               => 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";',
        append_on_no_match => true,
      }
    }
  }
}
