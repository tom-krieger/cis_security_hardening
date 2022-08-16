# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::apt_unused' do
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
            is_expected.to contain_file('/etc/apt/apt.conf.d/50unattended-upgrades')
              .with(
                'ensure' => 'file',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )

            is_expected.to contain_file_line('add Unattended-Upgrade::Remove-Unused-Dependencies')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/apt/apt.conf.d/50unattended-upgrades',
                'match'              => '^Unattended-Upgrade::Remove-Unused-Dependencies',
                'line'               => 'Unattended-Upgrade::Remove-Unused-Dependencies "true";',
                'append_on_no_match' => true,
              )

            is_expected.to contain_file_line('add Unattended-Upgrade::Remove-Unused-Kernel-Packages')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/apt/apt.conf.d/50unattended-upgrades',
                'match'              => '^Unattended-Upgrade::Remove-Unused-Kernel-Packages',
                'line'               => 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file('/etc/apt/apt.conf.d/50unattended-upgrades')
            is_expected.not_to contain_file_line('add Unattended-Upgrade::Remove-Unused-Dependencies')
            is_expected.not_to contain_file_line('add Unattended-Upgrade::Remove-Unused-Kernel-Packages')
          end
        }
      end
    end
  end
end
