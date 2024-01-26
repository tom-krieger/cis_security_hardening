# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::automatic_error_reporting' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              apport: {
                installed: true,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile.with_all_deps

          if enforce
            ensre = if os_facts[:os]['name'].casecmp('sles').zero?
                      'absent'
                    else
                      'purged'
                    end
            is_expected.to contain_package('apport')
              .with(
                'ensure' => ensre,
              )
          else
            is_expected.not_to contain_package('apport')
          end
        }
      end
    end
  end
end
