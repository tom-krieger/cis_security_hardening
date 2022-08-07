# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::sshd_crypto_policy' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:pre_condition) do
          <<-EOF
          exec { 'reload-sshd':
            command     => 'systemctl reload sshd',
            path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            refreshonly => true,
          }
          EOF
        end

        let(:facts) { os_facts }

        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            path = if os_facts[:operatingsystem] == 'SLES' && os_facts[:operatingsystemmajrelease] == '12'
                     '/usr/etc/ssh/sshd_config'
                   else
                     '/etc/ssh/sshd_config'
                   end
            is_expected.to contain_file_line('sshd-crypto-policy')
              .with(
                'ensure' => 'absent',
                'path'   => path,
                'match'             => '^\s*CRYPTO_POLICY\s*=.*',
                'match_for_absence' => true,
              )
              .that_notifies('Exec[reload-sshd]')
          else
            is_expected.not_to contain_file_line('sshd-crypto-policy')
          end
        }
      end
    end
  end
end
