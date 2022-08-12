# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::ctrl_alt_del_graphical' do
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
            is_expected.to contain_file('/etc/dconf/db/local.d/00-disable-CAD')
              .with(
                'ensure' => 'file',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )

            is_expected.to contain_ini_setting('ctrl-alt-del-graphical')
              .with(
                'ensure'  => 'present',
                'path'    => '/etc/dconf/db/local.d/00-disable-CAD',
                'section' => 'org/gnome/settings-daemon/plugins/media-keys',
                'setting' => 'logout',
                'value'   => '',
              )
              .that_requires('File[/etc/dconf/db/local.d/00-disable-CAD]')
          else
            is_expected.not_to contain_file('/etc/dconf/db/local.d/00-disable-CAD')
            is_expected.not_to contain_ini_setting('ctrl-alt-del-graphical')
          end
        }
      end
    end
  end
end
