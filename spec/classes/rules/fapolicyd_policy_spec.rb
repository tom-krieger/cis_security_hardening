# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::fapolicyd_policy' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:facts) do
          os_facts.merge!(
            cis_security_hardening: {
              abrt: {
                packages: ['abrt-libs', 'abrt-cli-ng', 'abrt-cli']
              }
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'permissive' => '1',
            'create_rules' => true,
          }
        end

        it { 
          is_expected.to compile 

          if enforce
            is_expected.to contain_file_line('fapolicyd_permissive')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/fapolicyd/fapolicyd.conf',
                'match'              => '^permissive =',
                'line'               => "permissive = 1",
                'append_on_no_match' => true,
              )
            is_expected.to contain_concat('/etc/fapolicyd/fapolicyd.mounts')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )
          else
            is_expected.not_to contain_file_line('fapolicyd_permissive')
            is_expected.not_to contain_concat('/etc/fapolicyd/fapolicyd.mounts')
          end
        }
      end
    end
  end
end
