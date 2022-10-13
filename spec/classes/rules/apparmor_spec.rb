# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::apparmor' do
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
            if os_facts[:osfamily].casecmp('debian').zero?
              is_expected.to contain_package('apparmor')
                .with(
                  'ensure' => 'installed',
                )
              is_expected.to contain_package('apparmor-utils')
                .with(
                  'ensure' => 'installed',
                )
            elsif os_facts[:osfamily].casecmp('suse').zero?
              is_expected.to contain_exec('install apparmor')
                .with(
                  'command' => 'zypper install -t pattern apparmor',
                  'path'    => ['/usr/bin', '/bin'],
                  'unless'  => 'rpm -q apparmor-docs apparmor-parser apparmor-profiles apparmor-utils libapparmor1',
                )
            end

          else
            is_expected.not_to contain_package('apparmor')
            is_expected.not_to contain_package('apparmor-utils')
            is_expected.not_to contain_exec('install apparmor')
          end
        }
      end
    end
  end
end
