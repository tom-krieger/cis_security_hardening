# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::system_cmd_group' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'system_dirs' => ['/bin', '/sbin'],
          }
        end

        it { 
          is_expected.to compile 

          if enforce 
            is_expected.to contain_file('/bin')
              .with(
                'group' => 'root',
              )
            
            is_expected.to contain_file('/sbin')
              .with(
                'group' => 'root',
              )
          else
            is_expected.not_to contain_file('/bin')
            is_expected.not_to contain_file('/sbin')
          end
        }
      end
    end
  end
end
