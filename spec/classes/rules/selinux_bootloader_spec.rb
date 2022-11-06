# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::selinux_bootloader' do
  test_on = {
    supported_os: [{
      'operatingsystem'        => 'RedHat',
      'operatingsystemrelease' => ['7', '8'],
    }]
  }

  on_supported_os(test_on).each do |os, os_facts|
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
            if facts[:operatingsystemmajrelease] >= '7'
              is_expected.to contain_file_line('cmdline_definition')
                .with(
                  'line'  => 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"',
                  'path'  => '/etc/default/grub',
                  'match' => '^GRUB_CMDLINE_LINUX_DEFAULT',
                )
                .that_notifies('Exec[selinux-grub-config]')
              is_expected.to contain_exec('selinux-grub-config')
                .with(
                  'command'     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
                  'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                  'refreshonly' => true,
                )
            else
              is_expected.not_to contain_file_line('cmdline_definition')
              is_expected.not_to contain_exec('selinux-grub-config')
            end
          else
            is_expected.not_to contain_file_line('cmdline_definition')
            is_expected.not_to contain_exec('selinux-grub-config')
          end
        }
      end
    end
  end
end
