# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gdm_screensaver' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'timeout' => 800,
            'lockdelay' => 4,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_exec('gdm screensaver enabled')
              .with(
                'command' => 'gsettings set org.gnome.desktop.session idle-delay "unit32 800"',
                'path'    => ['/bin', '/usr/bin'],
                'unless'  => 'test "$(gsettings get org.gnome.desktop.session idle-delay)" = "unit32 800"',
              )

            is_expected.to contain_exec('gdm screensaver ilde activates')
              .with(
                'command' => 'gsettings set org.gnome.desktop.screensaver idle-activation-enabled "true"',
                'path'    => ['/bin', '/usr/bin'],
                'unless'  => 'test "$(gsettings get org.gnome.desktop.session idle-delayidle-activation-enabled)" = "true"',
              )

            is_expected.to contain_exec('gdm screensaver locktime')
              .with(
                'command' => 'gsettings set org.gnome.desktop.screensaver lock-delay "unit32 4"',
                'path'    => ['/bin', '/usr/bin'],
                'unless'  => 'test "$(gsettings get org.gnome.desktop.screensaver lock-delay)" = "unit32 4"',
              )
          else
            is_expected.not_to contain_exec('gdm screensaver enabled')
            is_expected.not_to contain_exec('gdm screensaver ilde activates')
            is_expected.not_to contain_exec('gdm screensaver locktime')
          end
        }
      end
    end
  end
end
