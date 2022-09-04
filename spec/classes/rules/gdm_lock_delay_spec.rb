# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gdm_lock_delay' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'timeout' => 800,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_exec('gdm lock delay')
              .with(
                'command' => 'gsettings set org.gnome.desktop.screensaver lock-delay 800',
                'path'    => ['/bin', '/usr/bin'],
                'unless'  => 'test "$(gsettings get org.gnome.desktop.screensaver lock-delay)" = "800"',
              )
          else
            is_expected.not_to contain_exec('gdm lock delay')
          end
        }
      end
    end
  end
end
