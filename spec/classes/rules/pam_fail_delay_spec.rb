# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_fail_delay' do
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
            'delay' => 4_000_000,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_pam('pam-common-auth-fail-delay')
              .with(
                'ensure'    => 'present',
                'service'   => 'common-auth',
                'type'      => 'auth',
                'control'   => 'required',
                'module'    => 'pam_faildelay.so',
                'arguments' => ['delay=4000000'],
              )
          else
            is_expected.not_to contain_pam('pam-common-auth-fail-delay')
          end
        }
      end
    end
  end
end
