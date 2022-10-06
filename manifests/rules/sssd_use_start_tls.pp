# @summary
#    Ensure ldap_id_use_start_tls is set for LDAP.
#
# The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) 
# authentication communications setting ldap_id_use_start_tls.
#
# Rationale:
# Without cryptographic integrity protections, information can be altered by unauthorized users without detection. 
# Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using 
# asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the 
# confidentiality of the key used to generate the hash.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sssd_use_start_tls':
#     enforce = true,
#   }
#
# @api private
class cis_security_hardening::rules::sssd_use_start_tls (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_resource('file', '/etc/sssd/sssd.conf', {
        ensure => file,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
    })

    file_line { 'add ldap tls':
      ensure             => present,
      path               => '/etc/sssd/sssd.conf',
      match              => '^ldap_id_use_start_tls =',
      line               => 'ldap_id_use_start_tls = true',
      append_on_no_match => true,
    }
  }
}
