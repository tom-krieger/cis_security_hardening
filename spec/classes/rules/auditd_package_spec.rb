# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_package' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'packages' => ['audit', 'audit-libs'],
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_package('audit')
              .with(
                'ensure' => 'installed',
              )
            is_expected.to contain_package('audit-libs')
              .with(
                'ensure' => 'installed',
              )
          else
            is_expected.not_to contain_package('audit')
            is_expected.not_to contain_package('audit-libs')
          end
        }
      end
    end
  end
end
