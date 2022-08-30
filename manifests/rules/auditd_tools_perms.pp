# @summary 
#    Ensure audit tools are mode of 0755 or more restrictive and owned by the right user and group
#
# The operating system must configure audit tools with a mode of 0755 or less permissive.
#
# Rationale:
# Protecting audit information also includes identifying and protecting the tools used to view and 
# manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation 
# on audit information.
#
# Operating systems providing tools to interface with audit information will leverage user permissions 
# and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order 
# to make access decisions regarding the access to audit tools.
#
# Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to 
# successfully view and manipulate audit information system activity and records. Audit tools include 
# custom queries and report generators.
#
# Satisfies: SRG-OS-000256-GPOS-00097, SRG-OS-000257-GPOS-00098
#
# @param enforce
#    Enforce the rule.
# @param user
#    User to own auditd tools.
# @param group
#    Group to own the auditd tools.
# @param mode
#    Access permissions.
# @param tools
#    List of tools to work with.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_tools_perms':
#     ensure => true,
#     user => 'root',
#     group => 'root',
#     mode => '0755',
#
# @api public
class cis_security_hardening::rules::auditd_tools_perms (
  Boolean $enforce = false,
  String $user     = 'root',
  String $group    = 'root',
  String $mode     = '0755',
  Array $tools     = [],
) {
  if $enforce {
    $tools.each |$tool| {
      file { $tool:
        ensure => file,
        owner  => $user,
        group  => $group,
        mode   => $mode,
      }
    }
  }
}
