# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::dracut_fips' do
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
            is_expected.to contain_package('dracut-fips')
              .with(
                'ensure' => 'installed',
              )
              .that_notifies('Exec[recreate initramfs]')

            is_expected.to contain_exec('recreate initramfs')
              .with(
                'command'     => 'dracut -f',
                'path'        => ['/sin', '/usr/sbin', '/bin', '/usr/bin'],
                'refreshonly' => true,
              )
          else
            is_expected.not_to contain_package('dracut-fips')
            is_expected.not_to contain_exec('recreate initramfs')
          end
        }
      end
    end
  end
end
