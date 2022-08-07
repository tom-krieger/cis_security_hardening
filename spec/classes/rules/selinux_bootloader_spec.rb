# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::selinux_bootloader' do
  enforce_options.each do |enforce|
    context 'on RedHat' do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemmajrelease: '7',
          architecture: 'x86_64',
          mountpoints: {
            '/tmp/': {
              available: '1.85 GiB',
            },
            '/var/tmp': {
              available: '1.85 GiB',
            },
            '/dev/shm': {
              available: '1.85 GiB',
            },
          },
        }
      end

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
