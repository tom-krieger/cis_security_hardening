# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::disable_apport' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} nothing to do" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              apport: {
                pkg: false,
                service: false,
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
            is_expected.not_to contain_service('apport.service')
            is_expected.not_to contain_package('apport')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} nothing to do" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              apport: {
                pkg: true,
                service: true,
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
            is_expected.to contain_service('apport.service')
              .with(
                'ensure' => 'stopped',
                'enable' => false,
              )
            ens = if os_facts[:os]['family'].casecmp('suse').zero?
                    'absent'
                  else
                    'purged'
                  end
            is_expected.to contain_package('apport')
              .with(
                'ensure' => ens,
              )
          end
        }
      end
    end
  end
end
