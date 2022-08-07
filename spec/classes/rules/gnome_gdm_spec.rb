# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gnome_gdm' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            cis_security_hardening: {
              gnome_gdm_conf: false,
              gnome_gdm: true,
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if os_facts[:operatingsystem].casecmp('centos').zero? || os_facts[:operatingsystem].casecmp('almalinux').zero? || os_facts[:operatingsystem].casecmp('rocky').zero?

            if enforce
              is_expected.to contain_file('gdm')
                .with(
                  'ensure'  => 'file',
                  'path'    => '/etc/dconf/profile/gdm',
                  'content' => "user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults",
                )

              is_expected.to contain_file('banner-login')
                .with(
                  'ensure'  => 'file',
                  'path'    => '/etc/dconf/db/gdm.d/01-banner-message',
                  'content' => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=\'Authorized uses only. All activity may be monitored and reported.\'",
                )
                .that_requires('File[gdm]')
                .that_notifies('Exec[dconf-gdm-exec]')

              is_expected.to contain_exec('dconf-gdm-exec')
                .with(
                  'path'        => '/bin/',
                  'command'     => 'dconf update',
                  'refreshonly' => true,
                )

              is_expected.to contain_file('/etc/dconf/db/gdm.d')
                .with(
                  'ensure' => 'directory',
                  'owner'  => 'root',
                  'group'  => 'root',
                  'mode'   => '0755',
                )
            else
              is_expected.not_to contain_file('gdm')
              is_expected.not_to contain_file('banner-login')
              is_expected.not_to contain_exec('dconf-gdm-exec')
              is_expected.not_to contain_file('/etc/dconf/db/gdm.d')
            end

            is_expected.not_to contain_file('/etc/gdm3/greeter.dconf-defaults')
            is_expected.not_to contain_exec('dpkg-gdm-reconfigure')

          elsif os_facts[:operatingsystem].casecmp('ubuntu').zero?

            if enforce
              is_expected.to contain_file('/etc/gdm3/greeter.dconf-defaults')
                .with(
                  'ensure'  => 'file',
                  'owner'   => 'root',
                  'group'   => 'root',
                  'mode'    => '0644',
                )
                .that_notifies('Exec[dpkg-gdm-reconfigure]')

              is_expected.to contain_exec('dpkg-gdm-reconfigure')
                .with(
                  'path'        => ['/bin', '/usr/bin'],
                  'command'     => 'dpkg-reconfigure gdm3',
                  'refreshonly' => true,
                )
            else
              is_expected.not_to contain_file('/etc/gdm3/greeter.dconf-defaults')
              is_expected.not_to contain_exec('dpkg-gdm-reconfigure')
            end

            is_expected.not_to contain_file('gdm')
            is_expected.not_to contain_file('banner-login')
            is_expected.not_to contain_exec('dconf-gdm-exec')
            is_expected.not_to contain_file('/etc/dconf/db/gdm.d')

          elsif os_facts[:operatingsystem].casecmp('sles').zero?

            if enforce
              is_expected.to contain_file('/etc/dconf/profile/gdm')
                .with(
                  'ensure'  => 'file',
                  'content' => "user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n",
                  'owner'   => 'root',
                  'group'   => 'root',
                  'mode'    => '0644',
                )
                .that_notifies('Exec[dpkg-gdm-reconfigure]')

              is_expected.to contain_file('/etc/dconf/db/gdm.d/01-banner-message')
                .with(
                  'ensure'  => 'file',
                  'content' => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=\'Authorized uses only. All activity may be monitored and reported.\'", # lint:ignore:140chars
                  'owner'   => 'root',
                  'group'   => 'root',
                  'mode'    => '0644',
                )
                .that_notifies('Exec[dpkg-gdm-reconfigure]')

              is_expected.to contain_file('/etc/dconf/db/gdm.d/00- login-screen')
                .with(
                  'ensure'  => 'file',
                  'content' => "[org/gnome/login-screen]\ndisable-user-list=true\n",
                  'owner'   => 'root',
                  'group'   => 'root',
                  'mode'    => '0644',
                )
                .that_notifies('Exec[dpkg-gdm-reconfigure]')

              is_expected.to contain_exec('dpkg-gdm-reconfigure')
                .with(
                  'path'        => ['/bin', '/usr/bin'],
                  'command'     => 'dconf update',
                  'refreshonly' => true,
                )
            else
              is_expected.not_to contain_file('/etc/dconf/profile/gdm')
              is_expected.not_to contain_file('/etc/dconf/db/gdm.d/01-banner-message')
              is_expected.not_to contain_file('/etc/dconf/db/gdm.d/00- login-screen')
              is_expected.not_to contain_exec('dpkg-gdm-reconfigure')
            end
          end
        }
      end
    end
  end
end
