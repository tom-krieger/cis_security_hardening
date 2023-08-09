# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::grub_bootloader_config' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            if os_facts[:os]['family'].casecmp('redhat').zero?
              is_expected.to contain_file('/boot/grub2/grub.cfg')
                .with(
                  'ensure' => 'file',
                  'owner'  => 'root',
                  'group'  => 'root',
                  'mode'   => '0400',
                )

              if os_facts[:os]['release']['major'] >= '9'
                is_expected.to contain_file('/boot/grub2/grubenv')
                  .with(
                    'ensure' => 'file',
                    'owner'  => 'root',
                    'group'  => 'root',
                    'mode'   => '0600',
                  )

                is_expected.to contain_file('/boot/grub2/user.cfg')
                  .with(
                    'ensure' => 'file',
                    'owner'  => 'root',
                    'group'  => 'root',
                    'mode'   => '0600',
                  )
              else
                is_expected.not_to contain_file('/boot/grub2/grubenv')
                is_expected.not_to contain_file('/boot/grub2/user.cfg')
              end

            elsif os_facts[:os]['family'].casecmp('debian').zero?
              is_expected.to contain_file('/boot/grub/grub.cfg')
                .with(
                  'ensure' => 'file',
                  'owner'  => 'root',
                  'group'  => 'root',
                  'mode'   => '0400',
                )

              is_expected.to contain_file_line('correct grub.cfg permissions')
                .with(
                  'path'  => '/usr/sbin/grub-mkconfig',
                  'line'  => "  chmod 400 \${grub_cfg}.new || true",
                  'match' => '\s+chmod.*444',
                  'multiple' => true,
                  'replace_all_matches_not_matching_line' => true,
                  'append_on_no_match' => false,
                )
            elsif os_facts[:os]['family'].casecmp('suse').zero?
              is_expected.to contain_file('/boot/grub2/grub.cfg')
                .with(
                  'ensure' => 'file',
                  'owner'  => 'root',
                  'group'  => 'root',
                  'mode'   => '0400',
                )
            else
              is_expected.not_to contain_file('/boot/grub2/grub.cfg')
              is_expected.not_to contain_file('/boot/grub/grub.cfg')
              is_expected.not_to contain_file('/boot/grub2/grubenv')
              is_expected.not_to contain_file('/boot/grub2/user.cfg')
            end

          else
            is_expected.not_to contain_file('/boot/grub2/grub.cfg')
            is_expected.not_to contain_file('/boot/grub/grub.cfg')
            is_expected.not_to contain_file('/boot/grub2/grubenv')
            is_expected.not_to contain_file('/boot/grub2/user.cfg')
          end
        }
      end
    end
  end
end
