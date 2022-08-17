# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::iptables_loopback' do

  let(:pre_condition) do
    <<-EOF
    class { 'cis_security_hardening::rules::iptables_save':
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
            is_expected.to contain_firewall('001 accept all incoming traffic to local interface')
              .with(
                'chain'   => 'INPUT',
                'proto'   => 'all',
                'iniface' => 'lo',
                'action'  => 'accept',
              )

            is_expected.to contain_firewall('002 accept all outgoing traffic to local interface')
              .with(
                'chain'    => 'OUTPUT',
                'proto'    => 'all',
                'outiface' => 'lo',
                'action'   => 'accept',
              )

            is_expected.to contain_firewall('003 drop all traffic to lo 127.0.0.1/8')
              .with(
                'chain'   => 'INPUT',
                'proto'   => 'all',
                'source'  => '127.0.0.1/8',
                'action'  => 'drop',
              )
          else
            is_expected.not_to contain_firewall('001 accept all incoming traffic to local interface')
            is_expected.not_to contain_firewall('002 accept all outgoing traffic to local interface')
            is_expected.not_to contain_firewall('003 drop all traffic to lo 127.0.0.1/8')
          end
        }
      end
    end
  end
end
