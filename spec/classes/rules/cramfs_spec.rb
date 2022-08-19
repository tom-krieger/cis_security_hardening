# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::cramfs' do
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
            if os_facts[:operatingsystem].casecmp('rocky').zero?
              is_expected.to contain_kmod__install('cramfs')
                .with(
                  command: '/bin/false',
                )
              is_expected.to contain_kmod__blacklist('cramfs')
            else
              is_expected.to contain_kmod__install('cramfs')
                .with(
                  command: '/bin/true',
                )
            end
          else
            is_expected.not_to contain_kmod__install('cramfs')
            is_expected.not_to contain_kmod__blacklist('cramfs')
          end
        }
      end
    end
  end
end
