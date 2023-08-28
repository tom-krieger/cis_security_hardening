# @summary 
#    Ensure systemd-journal-remote is configured
#
# Journald (via systemd-journal-remote) supports the ability to send log events it gathers to a remote 
# log host or to receive messages from remote hosts, thus enabling centralised log management.
#
# Rationale:
# Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root 
# access on the local system, they could tamper with or remove log data that is stored on the local system.
#
# @param enforce
#    Enforce the rule.
#
# @param install_certs
#   Flag to control if certificates are installed
#
# @param server_key_file
#    SSL server key file.
# 
# @param server_cert_file
#    SSL server certificate file.
#
# @param trusted_cert_file
#    Trusted SSL certificate file
#
# @param url
#    Target IP to send logs to
#
# @example
#   class { 'cis_security_hardening::rules::systemd_journal_remote_config':
#     enforce => true,
#     url => '10.10.10.10',
#     server_key_file => '/etc/ssl/private/journal-upload.pem',
#     server_cert_file => '/etc/ssl/certs/journal-upload.pem',
#     trusted_cert_file => '/etc/ssl/ca/trusted.pem'
#   }
# 
# @api private
class cis_security_hardening::rules::systemd_journal_remote_config (
  Boolean $enforce = false,
  Boolean $install_certs = false,
  Stdlib::IP::Address $url = '1.2.3.4',
  Stdlib::Absolutepath $server_key_file = '/etc/ssl/private/journal-upload.pem',
  Stdlib::Absolutepath $server_cert_file = '/etc/ssl/certs/journal-upload.pem',
  Stdlib::Absolutepath $trusted_cert_file = '/etc/ssl/ca/trusted.pem'
) {
  if $enforce {
    file_line { 'systemd_journal_remote_config_url':
      ensure             => 'present',
      path               => '/etc/systemd/journal-upload.conf',
      line               => "URL=${url}",
      match              => '^#? URL=',
      append_on_no_match => true,
    }

    if $install_certs {
      file_line { 'systemd_journal_remote_config_server_key':
        ensure             => 'present',
        path               => '/etc/systemd/journal-upload.conf',
        line               => "ServerKeyFile=${server_key_file}",
        match              => '^#? ServerKeyFile=',
        append_on_no_match => true,
      }

      file_line { 'systemd_journal_remote_config_server_cert':
        ensure             => 'present',
        path               => '/etc/systemd/journal-upload.conf',
        line               => "ServerCertificateFile=${server_cert_file}",
        match              => '^#? ServerCertificateFile=',
        append_on_no_match => true,
      }

      file_line { 'systemd_journal_remote_config_trusted_cert':
        ensure             => 'present',
        path               => '/etc/systemd/journal-upload.conf',
        line               => "TrustedCertificateFile=${trusted_cert_file}",
        match              => '^#? TrustedCertificateFile=',
        append_on_no_match => true,
      }
    }
  }
}
