# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
uninstall_options = [true, false]

describe 'cis_security_hardening::rules::crond_service' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      uninstall_options.each do |uninstall|
        context "on #{os} with enforce = #{enforce}" do
          let(:facts) { os_facts }
          let(:params) do
            {
              'enforce' => enforce,
              'uninstall_cron' => uninstall,
            }
          end

          it {
            is_expected.to compile

            if enforce
              if uninstall
                is_expected.not_to contain_service('crond')

                if os_facts[:osfamily].casecmp('suse').zero?
                  is_expected.to contain_package('cronie')
                    .with(
                      'ensure' => 'absent',
                    )

                else
                  is_expected.to contain_package('cronie')
                    .with(
                      'ensure' => 'purged',
                    )
                end

              else

                if os_facts[:osfamily].casecmp('debian').zero? || os_facts[:osfamily].casecmp('suse').zero?
                  is_expected.to contain_service('cron')
                    .with(
                      'ensure' => 'running',
                      'enable' => true,
                    )
                else
                  is_expected.to contain_service('crond')
                    .with(
                      'ensure' => 'running',
                      'enable' => true,
                    )
                end

                is_expected.not_to contain_package('cronie')

              end
            else
              is_expected.not_to contain_service('crond')
              is_expected.not_to contain_package('cronie')
              is_expected.not_to contain_service('cron')
            end
          }
        end
      end
    end
  end
end
