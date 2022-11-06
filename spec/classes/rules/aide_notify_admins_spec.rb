# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::aide_notify_admins' do
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

          file = if os_facts[:os]['name'].casecmp('debian').zero? || os_facts[:os]['name'].casecmp('ubuntu').zero?
                   '/etc/default/aide'
                 else
                   '/etc/sysconfig/aide'
                 end

          if enforce
            is_expected.to contain_file_line('set silentreports to no')
              .with(
                'ensure'             => 'present',
                'path'               => file.to_s,
                'match'              => '^#?SILENTREPORTS',
                'line'               => 'SILENTREPORTS=no',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file_line('set silentreports to no')
          end
        }
      end
    end
  end
end
