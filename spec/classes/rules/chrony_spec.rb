# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::chrony' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'ntp_servers' => [
              { 'hostname' => '10.10.10.1' },
              { 'hostname' => '10.10.10.2' },
            ],
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_class('chrony')
              .with(
                'servers' => [
                  { 'hostname' => '10.10.10.1' },
                  { 'hostname' => '10.10.10.2' },
                ],
              )

            if os_facts[:operatingsystem].casecmp('ubuntu').zero?
              is_expected.to contain_package('ntp')
                .with(
                  'ensure' => 'purged',
                )
            end
          else
            is_expected.not_to contain_class('chrony')
            is_expected.not_to contain_package('ntp')
          end
        }
      end
    end
  end
end
