# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gdm_auto_mount' do
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
            is_expected.to contain_package('dconf')
              .with(
                'ensure' => 'present',
              )

            is_expected.to contain_file('/etc/dconf/db/local.d')
              .with(
                'ensure' => 'directory',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0755',
              )

            is_expected.to contain_file('/etc/dconf/db/local.d/00-media-automount')
              .with(
                'ensure' => 'file',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )

            is_expected.to contain_ini_setting('gdm-disable-automount')
              .with(
                 'ensure'  => 'present',
                 'path'    => '/etc/dconf/db/local.d/00-media-automount',
                 'section' => 'org/gnome/desktop/media-handling',
                 'setting' => 'automount',
                 'value'   => 'false',
               )
              .that_requires('File[/etc/dconf/db/local.d/00-media-automount]')
              .that_notifies('Exec[dconf update]')

            is_expected.to contain_ini_setting('gdm-disable-automount-open')
              .with(
                'ensure'  => 'present',
                'path'    => '/etc/dconf/db/local.d/00-media-automount',
                'section' => 'org/gnome/desktop/media-handling',
                'setting' => 'automount-open',
                'value'   => 'false',
              )
              .that_requires('File[/etc/dconf/db/local.d/00-media-automount]')
              .that_notifies('Exec[dconf update]')

            is_expected.to contain_exec('dconf update')
              .with(
                'command'     => 'dconf update',
                'path'        => ['/bin', '/usr/bin'],
                'refreshonly' => true,
              )
          else
            is_expected.not_to contain_package('dconf')
            is_expected.not_to contain_file('/etc/dconf/db/local.d')
            is_expected.not_to contain_file('/etc/dconf/db/local.d/00-media-automount')
            is_expected.not_to contain_ini_setting('gdm-disable-automount')
            is_expected.not_to contain_ini_setting('gdm-disable-automount-open')
            is_expected.not_to contain_exec('dconf update')
          end
        }
      end
    end
  end
end
