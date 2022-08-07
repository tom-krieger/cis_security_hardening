# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::logrotate_configuration' do
  enforce_options.each do |enforce|
    on_supported_os.each do |os, os_facts|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            cis_security_hardening: {
              logrotate_conf: {
                '/etc/logrotate.d/alternatives' => {
                  'action' => 'create',
                  'group' => 'root',
                  'mode' => '644',
                  'user' => 'root'
                }
              },
            },
          )
        end
        let(:params) do
          {
            'enforce'    => enforce,
            'permission' => '640'
          }
        end

        it {
          is_expected.to compile

          is_expected.to contain_file_line('change /etc/logrotate.d/alternatives')
            .with(
              'ensure' => 'present',
              'path'   => '/etc/logrotate.d/alternatives',
              'line'   => 'create 640 root root',
              'match'  => 'create 644 root root',
            )
        }
      end
    end
  end
end
