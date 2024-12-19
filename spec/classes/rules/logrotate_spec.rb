# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::logrotate' do
  let(:pre_condition) do
    <<-EOF
    package { 'rsyslog':
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

            is_expected.to create_class('logrotate')
              .with(
                'config' => {
                  'dateext'       => true,
                  'compress'      => true,
                  'delaycompress' => false,
                  'rotate'        => 7,
                  'rotate_every'  => 'week',
                  'ifempty'       => true,
                  'su'            => false,
                  'su_user'       => 'root',
                  'su_group'      => 'syslog',
                },
              )

          else
            is_expected.not_to create_class('logrotate')
          end
        }
      end
    end
  end
end
