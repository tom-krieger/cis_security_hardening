# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::disable_atm' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_kmod__install('ATM')
              .with(
                command: '/bin/true',
              )
            is_expected.to contain_kmod__blacklist('ATM')
          else
            is_expected.not_to contain_kmod__install('ATM')
            is_expected.not_to contain_kmod__blacklist('ATM')
          end
        }
      end
    end
  end
end
