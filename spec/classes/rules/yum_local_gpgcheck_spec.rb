# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::yum_local_gpgcheck' do
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

          if enforce
            is_expected.to contain_file_line('yum_localpkg_gpgcheck')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/yum.conf',
                'line'               => 'localpkg_gpgcheck=1',
                'match'              => '^localpkg_gpgcheck',
                'append_on_no_match' => true,
              )
            if os_facts[:os]['release']['major'] >= '8'
              is_expected.to contain_file_line('dnf_localpgk_gpgcheck')
                .with(
                  'ensure'             => 'present',
                  'path'               => '/etc/dnf/dnf.conf',
                  'line'               => 'localpkg_gpgcheck=1',
                  'match'              => '^localpkg_gpgcheck',
                  'append_on_no_match' => true,
                )
            end
          else
            is_expected.not_to contain_file_line('yum_localpkg_gpgcheck')
          end
        }
      end
    end
  end
end
