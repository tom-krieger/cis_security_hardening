# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::disable_tipc' do
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
            if os_facts[:os]['name'].casecmp('debian').zero?
              if os_facts[:os]['release']['major'] > '10'
                cmd = '/bin/false'
                is_expected.to contain_kmod__blacklist('tipc')
              else
                cmd = '/bin/true'
              end
            elsif os_facts[:os]['name'].casecmp('ubuntu').zero?
              if os_facts[:os]['release']['major'] >= '20'
                cmd = '/bin/false'
                is_expected.to contain_kmod__blacklist('tipc')
              else
                cmd = '/bin/true'
              end
            elsif os_facts[:os]['name'].casecmp('redhat').zero?
              if os_facts[:os]['release']['major'] > '8'
                cmd = '/bin/false'
                is_expected.to contain_kmod__blacklist('tipc')
              else
                cmd = '/bin/true'
              end
            else
              cmd = '/bin/true'
            end
            is_expected.to contain_kmod__install('tipc')
              .with(
                command: cmd,
              )
          else
            is_expected.not_to contain_kmod__install('tipc')
          end
        }
      end
    end
  end
end
