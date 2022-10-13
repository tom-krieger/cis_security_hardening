# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gdm_auto_mount' do
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

          if enforce
            is_expected.to contain_package('dconf')
              .with(
                'ensure' => 'installed',
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
                'content' => "[org/gnome/desktop/media-handling]\nautomount=false\nautomount-open=false\n",
              )
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
