# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::system_cmd_group' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            'cis_security_hardening' => {
              'system_command_files' => ['/sbin/pppd','/usr/sbin/pppd'],
            }
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
            is_expected.to contain_file('/sbin/pppd')
              .with(
                'group' => 'root',
              )
            
            is_expected.to contain_file('/usr/sbin/pppd')
              .with(
                'group' => 'root',
              )
          else
            is_expected.not_to contain_file('/sbin/pppd')
            is_expected.not_to contain_file('/usr/sbin/pppd')
          end
        }
      end
    end
  end
end
