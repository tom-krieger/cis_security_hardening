# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::user_namespaces' do
  let(:pre_condition) do
    <<-EOF
    exec { 'reload-sysctl-system':
      command     => 'sysctl --system',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
    EOF
  end

  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_sysctl('user.max_user_namespaces')
              .with(
                'value' => 0,
              )
              .that_notifies('Exec[reload-sysctl-system]')
          else
            is_expected.not_to contain_sysctl('user.max_user_namespaces')
          end
        }
      end
    end
  end
end
