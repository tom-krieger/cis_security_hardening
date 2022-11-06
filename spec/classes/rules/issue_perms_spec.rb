# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
file_options = ['', 'puppet:///modules/cis_security_hardening/dod_issue']

describe 'cis_security_hardening::rules::issue_perms' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} with file" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'content' => 'Testtext',
            'file'    => 'puppet:///modules/cis_security_hardening/dod_issue',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/etc/issue')
              .with(
                'ensure' => 'present',
                'source' => 'puppet:///modules/cis_security_hardening/dod_issue',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )
          else
            is_expected.not_to contain_file('/etc/issue')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} no content, no file}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'content' => :undef,
            'file' => :undef,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/etc/issue')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )
    
          else
            is_expected.not_to contain_file('/etc/issue')
          end
        }
      end
    end
  end
end
