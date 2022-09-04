# @summary
#    Ensure removal of software components after update
#
# The operating system must remove all software components after updated versions have been installed.
#
# Rationale:
# Previous versions of software components that are not removed from the information system after updates 
# have been installed may be exploited by adversaries. Some information technology products may remove older 
# versions of software automatically from the information system.
# 
# @param enforce
#    Enforce the rule.
#
# @example
#   Class { 'cis_security_hardening::rules::yum_clean_requirements':
#     enforce = true,
#   }
#
# @api private
class cis_security_hardening::rules::yum_clean_requirements (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'yum_clean_requirements_on_remove':
      ensure             => present,
      path               => '/etc/yum.conf',
      line               => 'clean_requirements_on_remove=1',
      match              => '^clean_requirements_on_remove',
      append_on_no_match => true,
    }
  }
}
