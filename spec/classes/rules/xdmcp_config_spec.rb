# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::xdmcp_config' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
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
            is_expected.to contain_file_line('remove enable')
              .with(
                'ensure'            => 'absent',
                'path'              => '/etc/gdm3/custom.conf',
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
