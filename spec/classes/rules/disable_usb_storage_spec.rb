# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::disable_usb_storage' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        let(:facts) { os_facts }

        it {
          is_expected.to compile
          if enforce
            cmd = if os_facts[:os]['name'].casecmp('debian').zero?
                    if os_facts[:os]['release']['major'] > '10'
                      '/bin/false'
                    else
                      '/bin/true'
                    end
                  else
                    '/bin/true'
                  end
            is_expected.to contain_kmod__install('usb-storage')
              .with(
                command: cmd,
              )
          else
            is_expected.not_to contain_kmod__install('usb-storage')
          end
        }
      end
    end
  end
end
