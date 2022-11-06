# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::yum_gpgcheck' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        let(:facts) { os_facts }

        it {
          is_expected.to compile

          if enforce && os_facts[:os]['family'].casecmp('redhat').zero?
            is_expected.to contain_file_line('yum_gpgcheck')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/yum.conf',
                'line'   => 'gpgcheck=1',
                'match'  => '^gpgcheck',
              )

            if os_facts[:os]['release']['major'].to_s > '7'
              is_expected.to contain_file_line('yum_gpgcheck dnf')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/dnf/dnf.conf',
                  'line'   => 'gpgcheck=1',
                  'match'  => '^gpgcheck',
                )
            end
          else
            is_expected.not_to contain_file_line('yum_gpgcheck')
            is_expected.not_to contain_file_line('yum_gpgcheck dnf')
          end
        }
      end
    end
  end
end
