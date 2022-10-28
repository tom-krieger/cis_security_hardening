# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
reboot_options = [true, false]

describe 'cis_security_hardening::rules::selinux_policy' do
  on_supported_os.each do |os, os_facts|
    reboot_options.each do |reboot|
      enforce_options.each do |enforce|
        context "on #{os} with enforce = #{enforce} and reboot = #{reboot}" do
          let(:pre_condition) do
            <<-EOF
            class { 'cis_security_hardening::reboot':
              auto_reboot => true,
              time_until_reboot => 120,
            }
            EOF
          end
          let(:facts) { os_facts }
          let(:params) do
            {
              'enforce' => enforce,
              'selinux_policy' => 'targeted',
              'auto_reboot' => reboot,
            }
          end

          it {
            is_expected.to compile

            if enforce
              if reboot
                is_expected.to contain_file('/etc/selinux/config')
                  .with(
                    'ensure' => 'present',
                    'owner'  => 'root',
                    'group'  => 'root',
                    'mode'   => '0644',
                  )
                  .that_notifies('Reboot[after_run]')

                is_expected.to contain_file_line('selinux_targeted')
                  .with(
                    'path'  => '/etc/selinux/config',
                    'line'  => 'SELINUXTYPE=targeted',
                    'match' => '^SELINUXTYPE=',
                  )
                  .that_notifies('Reboot[after_run]')
              else
                is_expected.to contain_file('/etc/selinux/config')
                  .with(
                    'ensure' => 'present',
                    'owner'  => 'root',
                    'group'  => 'root',
                    'mode'   => '0644',
                  )

                is_expected.to contain_file_line('selinux_targeted')
                  .with(
                    'path'  => '/etc/selinux/config',
                    'line'  => 'SELINUXTYPE=targeted',
                    'match' => '^SELINUXTYPE=',
                  )
              end
            else
              is_expected.not_to contain_file('/etc/selinux/config')
              is_expected.not_to contain_file_line('selinux_targeted')
            end
          }
        end
      end
    end
  end
end
