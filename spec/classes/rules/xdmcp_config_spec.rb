# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::xdmcp_config' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              xdcmp: true,
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
            filename = if os_facts[:os]['name'].casecmp('rocky').zero? || os_facts[:os]['name'].casecmp('almalinux').zero? ||
                          os_facts[:os]['name'].casecmp('centos').zero? || os_facts[:os]['name'].casecmp('redhat').zero?
                         '/etc/gdm/custom.conf'
                       else
                         '/etc/gdm3/custom.conf'
                       end

            is_expected.to contain_file_line('remove enable')
              .with(
                'ensure'            => 'absent',
                'path'              => filename,
                'match'             => 'Enable=true',
                'match_for_absence' => true,
              )
          else
            is_expected.not_to contain_file_line('remove enable')
          end
        }
      end
    end
  end
end
