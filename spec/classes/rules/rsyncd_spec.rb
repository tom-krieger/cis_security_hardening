# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::rsyncd' do
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

            if os_facts[:os]['family'].casecmp('debian').zero?

              is_expected.to contain_package('rsync')
                .with(
                  'ensure' => 'purged',
                )

              # if os_facts[:os]['name'].casecmp('debian').zero?
              is_expected.to contain_service('rsync')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
              # end

            elsif os_facts[:os]['family'].casecmp('suse').zero?

              is_expected.to contain_package('rsync')
                .with(
                  'ensure' => 'absent',
                )

            elsif os_facts[:os]['family'].casecmp('redhat').zero?

              if os_facts[:os]['release']['major'] > '6'
                is_expected.to contain_service('rsyncd')
                  .with(
                      'ensure' => 'stopped',
                      'enable' => false,
                    )
              else
                is_expected.to contain_service('rsync')
                  .with(
                    'ensure' => 'stopped',
                    'enable' => false,
                  )
              end

            end

          else
            is_expected.not_to contain_service('rsyncd')
            is_expected.not_to contain_package('rsync')
          end
        }
      end
    end
  end
end
