# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gdm_lock_enabled' do
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
            is_expected.to contain_exec('gdm lock enabled')
              .with(
                'command' => 'gsettings set org.gnome.desktop.screensaver lock-enabled true',
                'path'    => ['/bin', '/usr/bin'],
                'unless'  => 'test "$(gsettings get org.gnome.desktop.screensaver lock-enabled)" = "true"',
              )
          else
            is_expected.not_to contain_exec('gdm lock enabled')
          end
        }
      end
    end
  end
end
