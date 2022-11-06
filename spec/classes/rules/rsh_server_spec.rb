# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::rsh_server' do
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

          if enforce && (os_facts[:os]['family'].casecmp('ubuntu').zero? || os_facts[:os]['family'].casecmp('debian').zero?)
            is_expected.to contain_package('rsh-server')
              .with(
                'ensure' => 'purged',
              )
          else
            is_expected.not_to contain_package('rsh-server')
          end
        }
      end
    end
  end
end
