# @summary
#    Ensure logrotate assigns appropriate permissions
#
# Log files contain logged information from many services on the system, or on log 
# hosts others as well.
# 
# Rationale:
# It is important to ensure that log files have the correct permissions to ensure 
# that sensitive data is archived and protected.
#
# @param enforce
#    Enforce the rule
# @param permission
#    The file permission to use
#
# @example
#   class { 'cis_security_hardening::rules::logrotate_configuration':
#       enforce => true,
#       permission => '640'
#   }
#
# @api private
class cis_security_hardening::rules::logrotate_configuration (
  Boolean $enforce    = false,
  String $permission  = '640',
) {
  if
  cis_security_hardening::hash_key($facts, 'cis_security_hardening') and
  cis_security_hardening::hash_key($facts['cis_security_hardening'], 'logrotate_conf') {
    $facts['cis_security_hardening']['logrotate_conf'].each |$file, $data| {
      $match   = "${data['action']} ${data['mode']} ${data['user']} ${data['group']}"
      $replace = "${data['action']} ${permission} ${data['user']} ${data['group']}"

      file_line { "change ${file}":
        ensure => present,
        path   => $file,
        line   => $replace,
        match  => $match,
      }
    }
  }
}
