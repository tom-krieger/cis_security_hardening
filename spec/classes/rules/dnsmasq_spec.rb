# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::dnsmasq' do
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
          is_expected.to compile.with_all_deps

          if enforce
            if (os_facts[:os]['name'].casecmp('redhat').zero? || os_facts[:os]['name'].casecmp('centos').zero?) ||
               (os_facts[:os]['name'].casecmp('debian').zero? && os_facts[:os]['release']['major'] >= '12')
              is_expected.to contain_package('dnsmasq')
                .with(
                  'ensure' => 'purged',
                )
            else
              is_expected.not_to contain_package('dnsmasq')
            end
          else
            is_expected.not_to contain_package('dnsmasq')
          end
        }
      end
    end
  end
end
