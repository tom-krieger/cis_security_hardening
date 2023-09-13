# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::ip6tables_loopback' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} with ipv6" do
        let(:facts) do
          os_facts.merge(
            {
              'network6' => 'fe81::',
              'netmask6' => 'ffff:ffff:ffff:ffff::',
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_firewall('001-6 accept all incoming traffic to local interface')
              .with(
                'chain'   => 'INPUT',
                'proto'   => 'all',
                'iniface' => 'lo',
                'jump' => 'ACCEPT',
              )

            is_expected.to contain_firewall('002-6 accept all outgoing traffic to local interface')
              .with(
                'chain'    => 'OUTPUT',
                'proto'    => 'all',
                'outiface' => 'lo',
                'jump' => 'ACCEPT',
              )

            is_expected.to contain_firewall('003-6 drop all traffic to lo ::1')
              .with(
                'chain'   => 'INPUT',
                'proto'   => 'all',
                'source'  => '::1',
                'action'  => 'drop',
              )
          else
            is_expected.not_to contain_firewall('001-6 accept all incoming traffic to local interface')
            is_expected.not_to contain_firewall('002-6 accept all outgoing traffic to local interface')
            is_expected.not_to contain_firewall('003-6 drop all traffic to lo ::1')
          end
        }
      end
    end
  end
end
