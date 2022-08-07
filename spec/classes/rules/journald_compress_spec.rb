# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::journald_compress' do
  let(:pre_condition) do
    <<-EOF
    package { 'rsyslog':
      ensure => installed,
    }
    EOF
  end

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
            is_expected.to contain_file_line('journald compress')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/systemd/journald.conf',
                'line'               => 'Compress=yes',
                'match'              => '^Compress=',
                'append_on_no_match' => true,
              )
              .that_requires('Package[rsyslog]')
          else
            is_expected.not_to contain_file_line('journald compress')
          end
        }
      end
    end
  end
end
