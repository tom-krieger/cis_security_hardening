# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::sendmail' do
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
            ensureval = if os_facts[:os]['family'].casecmp('suse').zero?
                          'absent'
                        else
                          'purged'
                        end

            is_expected.to contain_package('sendmail')
              .with(
                'ensure' => ensureval,
              )
          else
            is_expected.not_to contain_package('sendmail')
          end
        }
      end
    end
  end
end
