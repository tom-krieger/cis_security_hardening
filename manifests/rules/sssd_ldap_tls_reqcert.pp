# @summary
#    Ensure ldap_tls_reqcert is set for LDAP.
#
# The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) 
# communications by setting ldap_tls_reqcert.
#
# Rationale:
# Without cryptographic integrity protections, information can be altered by unauthorized users without detection. 
# Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using 
# asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the 
# confidentiality of the key used to generate the hash.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sssd_ldap_tls_reqcert':
#     enforce = true,
#   }
#
# @api private
class cis_security_hardening::rules::sssd_ldap_tls_reqcert (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_resource('file', '/etc/sssd/sssd.conf', {
        ensure => file,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
    })

    file_line { 'add ldap reqcert':
      ensure             => present,
      path               => '/etc/sssd/sssd.conf',
      match              => '^ldap_tls_reqcert =',
      line               => 'ldap_tls_reqcert = demand',
      append_on_no_match => true,
    }
  }
}
