# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::automatic_error_reporting' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce #{enforce} and apport installed" do
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
            'delete_package'=> true,
          }
        end

        it {
          is_expected.to compile.with_all_deps

          if enforce
            is_expected.to contain_service('apport')
              .with(
                'ensure' => 'stopped',
                'enable' => false,
              )

            is_expected.to contain_exec('mask apport daemon')
              .with(
                'command' => 'systemctl mask apport',
                'path'    => ['/bin', '/usr/bin'],
                'onlyif'  => 'test $(systemctl is-enabled apport) = "enabled"',
              )
          
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

      context "on #{os} with enforce #{enforce} and apport not installed" do
        let(:facts) do
          os_facts.merge
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile.with_all_deps
          is_expected.not_to contain_package('apport')
        }
      end
    end
  end
end
