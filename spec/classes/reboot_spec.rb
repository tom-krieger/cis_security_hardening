# frozen_string_literal: true

require 'spec_helper'

auto_reboot_options = [true, false]

describe 'cis_security_hardening::reboot' do
  on_supported_os.each do |os, os_facts|
    auto_reboot_options.each do |auto_reboot|
      context "on #{os} with auto_reboot #{auto_reboot}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'auto_reboot' => auto_reboot,
            'time_until_reboot' => 120,
          }
        end

        it { 
          is_expected.to compile 

          if auto_reboot
            is_expected.to contain_reboot('after_run')
              .with(
                'timeout' => 120,
                'message' => 'forced reboot by Puppet',
                'apply'   => 'finished',
              )
          else
            is_expected.not_to contain_reboot('after_run')
          end
        }
      end
    end
  end
end
