# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::sshd_install' do
  on_supported_os.each do |_os, os_facts|
    enforce_options.each do |enforce|
      context 'on RedHat' do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_package('ssh')
              .with(
                'ensure' => 'present',
              )
            is_expected.to contain_service('sshd')
              .with(
                'enable' => true,
                'ensure' => 'running',
              )
          else
            is_expected.not_to contain_package('ssh')
            is_expected.not_to contain_service('sshd')
          end
        }
      end
    end
  end
end
