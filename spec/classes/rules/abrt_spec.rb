# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::abrt' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            cis_security_hardening: {
              abrt: {
                packages: ['abrt-libs', 'abrt-cli-ng', 'abrt-cli']
              }
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            ensureval = if os_facts[:os]['family'].casecmp('suse').zero?
                          'absent'
                        else
                          'purged'
                        end

            is_expected.to contain_package('abrt-libs')
              .with(
                'ensure' => ensureval,
              )
            is_expected.to contain_package('abrt-cli-ng')
              .with(
                'ensure' => ensureval,
              )
            is_expected.to contain_package('abrt-cli')
              .with(
                'ensure' => ensureval,
              )
          else
            is_expected.not_to contain_package('abrt-libs')
            is_expected.not_to contain_package('abrt-cli-ng')
            is_expected.not_to contain_package('abrt-cli')
          end
        }
      end
    end
  end
end
