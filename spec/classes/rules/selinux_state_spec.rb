# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
reboot_options = [true, false]

describe 'cis_security_hardening::rules::selinux_state' do
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
              'state' => 'enforcing',
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
                  .that_notifies('Class[cis_security_hardening::reboot]')

                is_expected.to contain_file_line('selinux_enforce')
                  .with(
                    'path'     => '/etc/selinux/config',
                    'line'     => 'SELINUX=enforcing',
                    'match'    => 'SELINUX=',
                    'multiple' => true,
                  )
                  .that_notifies('Class[cis_security_hardening::reboot]')
              else
                is_expected.to contain_file('/etc/selinux/config')
                  .with(
                    'ensure' => 'present',
                    'owner'  => 'root',
                    'group'  => 'root',
                    'mode'   => '0644',
                  )

                is_expected.to contain_file_line('selinux_enforce')
                  .with(
                    'path'     => '/etc/selinux/config',
                    'line'     => 'SELINUX=enforcing',
                    'match'    => 'SELINUX=',
                    'multiple' => true,
                  )
              end

            else
              is_expected.not_to contain_file('/etc/selinux/config')
              is_expected.not_to contain_file_line('selinux_enforce')
              is_expected.not_to contain_exec('ensure selinux active')
            end
          }
        end
      end
    end
  end
end
