# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::cramfs' do
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
            if os_facts[:os]['name'].casecmp('rocky').zero? || os_facts[:os]['name'].casecmp('almalinux').zero?
              is_expected.to contain_kmod__install('cramfs')
                .with(
                  command: '/bin/false',
                )
              is_expected.to contain_kmod__blacklist('cramfs')
            elsif os_facts[:os]['name'].casecmp('redhat').zero? || os_facts[:os]['name'].casecmp('centos').zero?
              if os_facts[:os]['release']['major'] > '7'
                is_expected.to contain_kmod__install('cramfs')
                  .with(
                  command: '/bin/false',
                )
                is_expected.to contain_kmod__blacklist('cramfs')
              else
                is_expected.to contain_kmod__install('cramfs')
                  .with(
                  command: '/bin/true',
                )
              end
            elsif os_facts[:os]['name'].casecmp('debian').zero?
              if os_facts[:os]['release']['major'] > '10'
                is_expected.to contain_kmod__install('cramfs')
                  .with(
                  command: '/bin/false',
                )
                is_expected.to contain_kmod__blacklist('cramfs')
              else
                is_expected.to contain_kmod__install('cramfs')
                  .with(
                  command: '/bin/true',
                )
              end
            elsif os_facts[:os]['name'].casecmp('ubuntu').zero?
              if os_facts[:os]['release']['major'] >= '20'
                is_expected.to contain_kmod__install('cramfs')
                  .with(
                  command: '/bin/false',
                )
                is_expected.to contain_kmod__blacklist('cramfs')
              else
                is_expected.to contain_kmod__install('cramfs')
                  .with(
                  command: '/bin/true',
                )
              end
            else
              is_expected.to contain_kmod__install('cramfs')
                .with(
                  command: '/bin/true',
                )
            end
          else
            is_expected.not_to contain_kmod__install('cramfs')
            is_expected.not_to contain_kmod__blacklist('cramfs')
          end
        }
      end
    end
  end
end
