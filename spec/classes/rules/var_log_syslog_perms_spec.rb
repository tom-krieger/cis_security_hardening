# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::var_log_syslog_perms' do
  on_supported_os.each do |_os, os_facts|
    enforce_options.each do |enforce|
      context 'on RedHat' do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'user' => 'syslog',
            'group' => 'adm',
            'mode' => '0640',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/var/log/syslog')
              .with(
                'ensure' => 'file',
                'owner' => 'syslog',
                'group' => 'adm',
                'mode' => '0640',
              )
          else
            is_expected.not_to contain_file('/var/log/syslog')
          end
        }
      end
    end
  end
end
