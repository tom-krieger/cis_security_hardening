require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::ufw_service' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              services_enabled: {
                srv_ufw: 'disabled',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_service('ufw')
              .with(
                'ensure' => 'running',
                'enable' => true,
              )
            is_expected.to contain_exec('enable-ufw')
              .with(
                'command' => 'ufw --force enable',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'unless'  => 'test -z "$(ufw status | grep \"Status: inactive\")"',
              )

          else
            is_expected.not_to contain_service('ufw')
            is_expected.not_to contain_exec('enable-ufw')
          end
        end
      end
    end
  end
end
