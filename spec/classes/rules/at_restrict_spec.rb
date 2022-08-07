# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::at_restrict' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/etc/at.allow')
              .with(
                'ensure' => 'file',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0600',
              )

            is_expected.to contain_file('/etc/at.deny')
              .with(
                'ensure' => 'absent',
              )
          else
            is_expected.not_to contain_file('/etc/at.allow')
            is_expected.not_to contain_file('/etc/at.deny')
          end
        }
      end
    end
  end
end
