# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::grub_password' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|

      context "on #{os} with enforce = #{enforce} without grub password provided" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'grub_password_pbkdf2' => :undef,
          }
        end

        it { 
          if enforce
            is_expected.to compile.and_raise_error(%r{Enforcing a grub boot password needs a grub password to be defined. Please define an encrypted grub password in Hiera.})
          else
            is_expected.to compile
          end
        }
      end

      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'grub_password_pbkdf2' => 'grub.pbkdf2.sha512.10000.943.....',
          }
        end

        it {
          is_expected.to compile

          efi_grub_cfg = "/boot/efi/EFI/#{os_facts[:os]['name'].downcase}/grub.cfg"

          if os_facts[:os]['family'].casecmp('redhat').zero?

            is_expected.not_to contain_file('/etc/grub.d/user.cfg')
            is_expected.not_to contain_exec('bootpw-grub-config-ubuntu')
            is_expected.not_to contain_exec('bootpw-grub-config-ubuntu-efi')

            if enforce
              is_expected.to contain_file('/boot/grub2/user.cfg')
                .with(
                  'ensure' => 'file',
                  'owner'  => 'root',
                  'group'  => 'root',
                  'mode'   => '0600',
                )
                .that_notifies('Exec[bootpw-grub-config]')

              is_expected.to contain_exec('bootpw-grub-config')
                .with(
                  'command'     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
                  'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                  'refreshonly' => true,
                )

              is_expected.to contain_exec('bootpw-grub-config-efi')
                .with(
                  'command'     => "grub2-mkconfig -o #{efi_grub_cfg}",
                  'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                  'refreshonly' => true,
                )

            end

          elsif os_facts[:os]['family'].casecmp('debian').zero?

            is_expected.not_to contain_file('/boot/grub2/user.cfg')
            is_expected.not_to contain_exec('bootpw-grub-config')

            if enforce
              is_expected.to contain_file('/etc/grub.d/50_custom')
                .with(
                  'ensure' => 'file',
                  'owner'  => 'root',
                  'group'  => 'root',
                  'mode'   => '0755',
                )
                .that_notifies('Exec[bootpw-grub-config-ubuntu]')

              is_expected.to contain_file_line('grub-unrestricted')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/grub.d/10_linux',
                  'line'   => 'CLASS="--class gnu-linux --class gnu --class os --unrestricted"',
                  'match'  => '^CLASS="--class gnu-linux --class gnu --class os"',
                  'append_on_no_match' => false,
                )
                .that_notifies('Exec[bootpw-grub-config-ubuntu]')

              is_expected.to contain_exec('bootpw-grub-config-ubuntu')
                .with(
                  'command'     => 'update-grub',
                  'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                  'refreshonly' => true,
                )

              is_expected.to contain_exec('bootpw-grub-config-ubuntu-efi')
                .with(
                  'command'     => "update-grub -o #{efi_grub_cfg}",
                  'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                  'refreshonly' => true,
                )
            else
              is_expected.not_to contain_file('/etc/grub.d/50_custom')
              is_expected.not_to contain_exec('bootpw-grub-config-ubuntu')
              is_expected.not_to contain_exec('bootpw-grub-config-ubuntu-efi')
              is_expected.not_to contain_file_line('grub-unrestricted')
            end

          elsif os_facts[:os]['family'].casecmp('suse').zero?

            is_expected.not_to contain_file('/boot/grub2/user.cfg')
            is_expected.not_to contain_exec('bootpw-grub-config')
            is_expected.not_to contain_file('/etc/grub.d/50_custom')
            is_expected.not_to contain_exec('bootpw-grub-config-ubuntu')
            is_expected.not_to contain_file_line('grub-unrestricted')

            if enforce
              is_expected.to contain_file('/etc/grub.d/40_custom')
                .with(
                  'ensure'  => 'file',
                  'owner'   => 'root',
                  'group'   => 'root',
                  'mode'    => '0755',
                )
                .that_notifies('Exec[bootpw-grub-config-sles]')

              is_expected.to contain_exec('bootpw-grub-config-sles')
                .with(
                  'command'     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
                  'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                  'refreshonly' => true,
                )

              is_expected.to contain_exec('bootpw-grub-config-sles-efi')
                .with(
                  'command'     => "grub2-mkconfig -o #{efi_grub_cfg}",
                  'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                  'refreshonly' => true,
                )
            end

          end
        }
      end
    end
  end
end
