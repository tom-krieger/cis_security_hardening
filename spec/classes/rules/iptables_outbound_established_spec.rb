# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::iptables_outbound_established' do
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
            is_expected.to contain_firewall('004 accept outbound tcp state new, established')
              .with(
                'chain'  => 'OUTPUT',
                'proto'  => 'tcp',
                'state'  => ['NEW', 'ESTABLISHED'],
                'action' => 'accept',
              )

            is_expected.to contain_firewall('005 accept outbound udp state new, established')
              .with(
                'chain'  => 'OUTPUT',
                'proto'  => 'udp',
                'state'  => ['NEW', 'ESTABLISHED'],
                'action' => 'accept',
              )

            is_expected.to contain_firewall('006 accept outbound icmp state new, established')
              .with(
                'chain'  => 'OUTPUT',
                'proto'  => 'icmp',
                'state'  => ['NEW', 'ESTABLISHED'],
                'action' => 'accept',
              )

            is_expected.to contain_firewall('007 accept inbound tcp state established')
              .with(
                'chain'  => 'INPUT',
                'proto'  => 'tcp',
                'state'  => 'ESTABLISHED',
                'action' => 'accept',
              )

            is_expected.to contain_firewall('008 accept inbound udp state established')
              .with(
                'chain'  => 'INPUT',
                'proto'  => 'udp',
                'state'  => 'ESTABLISHED',
                'action' => 'accept',
              )

            is_expected.to contain_firewall('009 accept inbound icmp state established')
              .with(
                'chain'  => 'INPUT',
                'proto'  => 'icmp',
                'state'  => 'ESTABLISHED',
                'action' => 'accept',
              )
          else
            is_expected.not_to contain_firewall('004 accept outbound tcp state new, established')
            is_expected.not_to contain_firewall('005 accept outbound udp state new, established')
            is_expected.not_to contain_firewall('006 accept outbound icmp state new, established')
            is_expected.not_to contain_firewall('007 accept inbound tcp state established')
            is_expected.not_to contain_firewall('008 accept inbound udp state established')
            is_expected.not_to contain_firewall('009 accept inbound icmp state established')
          end
        }
      end
    end
  end
end
