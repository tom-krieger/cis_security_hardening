# frozen_string_literal: true

require 'spec_helper'

postrun_options = [true, false]

describe 'cis_security_hardening' do
  on_supported_os.each do |os, os_facts|
    postrun_options.each do |postrun|
      context "on #{os} with postrun = #{postrun}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'level' => '2',
            'update_postrun_command' => postrun,
          }
        end

        it {
          os_vers = if os_facts[:operatingsystem].casecmp('ubuntu').zero?
                      os_facts[:operatingsystemmajrelease].split("/\./")
                    else
                      os_facts[:operatingsystemmajrelease]
                    end

          key = "cis_security_hardening::benchmark::#{os_facts[:operatingsystem]}::#{os_vers}"
          # is_expected.to compile
          is_expected.to compile.with_all_deps
          is_expected.to contain_class('cis_security_hardening::services')
          is_expected.to contain_class('cis_security_hardening::config')
          is_expected.to contain_class('cis_security_hardening::auditd_cron')

          unless os_facts[:operatingsystem].casecmp('ubuntu').zero? ||
                 os_facts[:operatingsystem].casecmp('debian').zero? ||
                 os_facts[:operatingsystem].casecmp('centos').zero? ||
                 os_facts[:operatingsystem].casecmp('redhat').zero? ||
                 os_facts[:operatingsystem].casecmp('almalinux').zero? ||
                 os_facts[:operatingsystem].casecmp('rocky').zero? ||
                 os_facts[:operatingsystem].casecmp('sles').zero?

            is_expected.to contain_echo('no bundles')
              .with(
                'message'  => "No bundles found, enforcing nothing. (key = #{key})",
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
