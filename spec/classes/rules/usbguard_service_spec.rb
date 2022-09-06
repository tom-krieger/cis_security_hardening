# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::usbguard_service' do
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
            is_expected.to contain_service('usbguard')
              .with(
                'ensure' => 'running',
                'enable' => true,
              )
          else
            is_expected.not_to contain_service('usbguard')
          end
        }
      end
    end
  end
end
