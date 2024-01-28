# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::freevxfs' do
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
            if os_facts[:os]['name'].casecmp('ubuntu').zero? && os_facts[:os]['release']['major'] >= '20'
              is_expected.to contain_kmod__install('freevxfs')
                .with(
                  command: '/bin/false',
                )
              is_expected.to contain_kmod__blacklist('freevxfs')
            else
              is_expected.to contain_kmod__install('freevxfs')
                .with(
                  command: '/bin/true',
                )
            end
          else
            is_expected.not_to contain_kmod__install('freevxfs')
          end
        }
      end
    end
  end
end
