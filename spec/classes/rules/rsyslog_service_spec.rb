# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::rsyslog_service' do
  let(:pre_condition) do
    <<-EOF
    package{'rsyslog':
      ensure => installed,
    }
    EOF
  end

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
            is_expected.to contain_service('rsyslog')
              .with(
                'ensure' => 'running',
                'enable' => true,
              )
              .that_requires('Package[rsyslog]')
          else
            is_expected.not_to contain_service('rsyslog')
          end
        }
      end
    end
  end
end
