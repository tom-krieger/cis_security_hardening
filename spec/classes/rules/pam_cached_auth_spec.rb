# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_cached_auth' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge!(
            'cis_security_hardening' => {
              'systemd-coredump' => 'yes',
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('pam cached auth')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/sssd/sssd.conf',
                'line'   => 'offline_credentials_expiration = 1',
                'match'  => '^#?offline_credentials_expiration',
              )
          else
            is_expected.not_to contain_file_line('pam cached auth')
          end
        }
      end
    end
  end
end
