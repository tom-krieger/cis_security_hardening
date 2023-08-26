# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::systemd_journal_remote_config' do
  enforce_options.each do |enforce|
    context "on Ubuntu with enforce #{enforce}" do
      let(:facts) do
        {
          'os' => {
            'architecture' => 'x86_64',
            'family' => 'Debian',
            'name' => 'Ubuntu',
            'release' => {
              'major' => '22.04',
            }
          }
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'url' => '1.2.3.4',
          'server_key_file' => '/etc/ssl/private/journal-upload.pem',
          'server_cert_file' => '/etc/ssl/certs/journal-upload.pem',
          'trusted_cert_file' => '/etc/ssl/ca/trusted.pem'
        }
      end

      it {
        is_expected.to compile.with_all_deps

        if enforce
          is_expected.to contain_file_line('systemd_journal_remote_config_url')
            .with(
              'ensure'             => 'present',
              'path'               => '/etc/systemd/journal-upload.conf',
              'line'               => 'URL=1.2.3.4',
              'match'              => '^#? URL=',
              'append_on_no_match' => true,
            )

          is_expected.to contain_file_line('systemd_journal_remote_config_server_key')
            .with(
              'ensure'             => 'present',
              'path'               => '/etc/systemd/journal-upload.conf',
              'line'               => 'ServerKeyFile=/etc/ssl/private/journal-upload.pem',
              'match'              => '^#? ServerKeyFile=',
              'append_on_no_match' => true,
            )

          is_expected.to contain_file_line('systemd_journal_remote_config_server_cert')
            .with(
              'ensure'             => 'present',
              'path'               => '/etc/systemd/journal-upload.conf',
              'line'               => 'ServerCertificateFile=/etc/ssl/certs/journal-upload.pem',
              'match'              => '^#? ServerCertificateFile=',
              'append_on_no_match' => true,
            )

          is_expected.to contain_file_line('systemd_journal_remote_config_trusted_cert')
            .with(
              'ensure'             => 'present',
              'path'               => '/etc/systemd/journal-upload.conf',
              'line'               => 'TrustedCertificateFile=/etc/ssl/ca/trusted.pem',
              'match'              => '^#? TrustedCertificateFile=',
              'append_on_no_match' => true,
            )
        else
          is_expected.not_to contain_file_line('systemd_journal_remote_config_url')
          is_expected.not_to contain_file_line('systemd_journal_remote_config_server_key')
          is_expected.not_to contain_file_line('systemd_journal_remote_config_server_cert')
          is_expected.not_to contain_file_line('systemd_journal_remote_config_trusted_cert')
        end
      }
    end
  end
end
