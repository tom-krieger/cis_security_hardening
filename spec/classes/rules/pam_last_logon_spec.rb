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
            is_expected.to contain_pam("pam-login-last-logon-#{service}")
              .with(
                'ensure'    => 'present',
                'service'   => service,
                'type'      => 'session',
                'control'   => 'required',
                'module'    => 'pam_lastlog.so',
                'arguments' => ['showfailed'],
              )
          else
            is_expected.not_to contain_pam("pam-login-last-logon-#{service}")
          end
        }
      end
    end
  end
end
