# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::krb5_server' do
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
            ensureval = if os_facts[:osfamily].casecmp('suse').zero?
                          'absent'
                        else
                          'purged'
                        end

            is_expected.to contain_package('krb5-server')
              .with(
                'ensure' => ensureval,
              )
          else
            is_expected.not_to contain_package('krb5-server')
          end
        }
      end
    end
  end
end
