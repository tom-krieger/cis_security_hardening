# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_log_dir_perms' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            cis_security_hardening: {
              auditd: {
                auditing_process: 'none',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'user' => 'root',
            'group' => 'root',
            'mode' => '0750',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/var/log/audit')
              .with(
                'ensure' => 'directory',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0750',
              )
          else
            is_expected.not_to contain_file('/var/log/audit')
          end
        }
      end
    end
  end
end
