# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_last_logon' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge!(
            'cis_security_hardening' => {
              'systemd-coredump' => 'yes',
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

          service = if os_facts[:operatingsystem].casecmp('redhat').zero? && os_facts[:operatingsystemmajrelease] == '7'
                      'postlogin'
                    else
                      'login'
                    end

          if enforce
            is_expected.to contain_file_line('pam last logon')
              .with(
                'ensure'             => 'present',
                'path'               => "/etc/pam.d/#{service}",
                'match'              => 'session\s+required\s+pam_lastlog.so',
                'line'               => 'session      required      pam_lastlog.so showfailed',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_pam('pam-login-last-logon')
          end
        }
      end
    end
  end
end
