# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::fips_bootloader' do
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
              is_expected.to contain_exec('fips-grub-config')
                .with(
                  'command'     => 'update-grub',
                  'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                  'refreshonly' => true,
                )

              is_expected.to contain_kernel_parameter('fips')
                .with(
                  'value' => '1',
                )
                .that_notifies('Exec[fips-grub-config]')

            elsif os_facts[:osfamily].casecmp('suse').zero?
              is_expected.to contain_exec('fips-grub-config')
                .with(
                  'command'     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
                  'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                  'refreshonly' => true,
                )

              is_expected.to contain_kernel_parameter('fips')
                .with(
                  'value' => '1',
                )
                .that_notifies('Exec[fips-grub-config]')
            end
          else
            is_expected.not_to contain_exec('fips-grub-config')
            is_expected.not_to contain_kernel_parameter('fips')
          end
        }
      end
    end
  end
end
