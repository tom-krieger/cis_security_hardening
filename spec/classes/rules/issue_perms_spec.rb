# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
file_options = ['', 'puppet:///modules/cis_security_hardening/dod_issue']

describe 'cis_security_hardening::rules::issue_perms' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      file_options.each do |file|
        context "on #{os} with enforce = #{enforce} / file = #{file}" do
          let(:facts) { os_facts }
          let(:params) do
            {
              'enforce' => enforce,
              'content' => 'Testtext',
              'file' => file,
            }
          end

          it {
            is_expected.to compile

            if enforce
              if file.empty?
                is_expected.to contain_file('/etc/issue')
                  .with(
                    'ensure' => 'present',
                    'content' => 'Testtext',
                    'owner'  => 'root',
                    'group'  => 'root',
                    'mode'   => '0644',
                  )
              else
                is_expected.to contain_file('/etc/issue')
                  .with(
                    'ensure' => 'present',
                    'source' => 'puppet:///modules/cis_security_hardening/dod_issue',
                    'owner'  => 'root',
                    'group'  => 'root',
                    'mode'   => '0644',
                  )
              end

            else
              is_expected.not_to contain_file('/etc/issue')
            end
          }
        end
      end
    end
  end
end
