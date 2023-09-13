# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::ip6tables_outbound_established' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} with ipv6" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'ip6tables' => {
                'policy' => {
                  'rule 1' => {
                    'chain' => 'INPUT',
                    'dpt' => '',
                    'dst' => '0.0.0.0/0',
                    'icmptype' => '',
                    'in' => 'lo',
                    'info' => '/* 001 accept all incoming traffic to local interface */',
                    'opts' => '--',
                    'out' => '*',
                    'proto' => 'all',
                    'spt' => '',
                    'src' => '0.0.0.0/0',
                    'state' => '',
                    'target' => 'ACCEPT',
                  },
                  'rule 10' => {
                    'chain' => 'OUTPUT',
                    'dpt' => '',
                    'dst' => '0.0.0.0/0',
                    'icmptype' => '',
                    'in' => '*',
                    'info' => 'state NEW,ESTABLISHED /* 006 accept outbound icmp state new, established */',
                    'opts' => '--',
                    'out' => '*',
                    'proto' => 'icmp',
                    'spt' => '',
                    'src' => '0.0.0.0/0',
                    'state' => 'NEW,ESTABLISHED',
                    'target' => 'ACCEPT',
                  },
                  'rule 11' => {
                    'chain' => 'OUTPUT',
                    'dpt' => '',
                    'dst' => '0.0.0.0/0',
                    'icmptype' => '',
                    'in' => '*',
                    'info' => 'multiport dports 53 state NEW /* 103 dns udp outbound */',
                    'opts' => '--',
                    'out' => '*',
                    'proto' => 'udp',
                    'spt' => '',
                    'src' => '0.0.0.0/0',
                    'state' => 'NEW',
                    'target' => 'ACCEPT',
                  },
                  'rule 12' => {
                    'chain' => 'OUTPUT',
                    'dpt' => '',
                    'dst' => '0.0.0.0/0',
                    'icmptype' => '',
                    'in' => '*',
                    'info' => 'multiport dports 53 state NEW /* 104 dns tcp inbound */',
                    'opts' => '--',
                    'out' => '*',
                    'proto' => 'tcp',
                    'spt' => '',
                    'src' => '0.0.0.0/0',
                    'state' => 'NEW',
                    'target' => 'ACCEPT',
                  },
                  'rule 2' => {
                    'chain' => 'INPUT',
                    'dpt' => '',
                    'dst' => '0.0.0.0/0',
                    'icmptype' => '',
                    'in' => '*',
                    'info' => '/* 003 drop all traffic to lo 127.0.0.1/8 */',
                    'opts' => '--',
                    'out' => '*',
                    'proto' => 'all',
                    'spt' => '',
                    'src' => '127.0.0.0/8',
                    'state' => '',
                    'target' => 'DROP',
                  },
                  'rule 3' => {
                    'chain' => 'INPUT',
                    'dpt' => '',
                    'dst' => '0.0.0.0/0',
                    'icmptype' => '',
                    'in' => '*',
                    'info' => 'state ESTABLISHED /* 008 accept inbound udp state established */',
                    'opts' => '--',
                    'out' => '*',
                    'proto' => 'udp',
                    'spt' => '',
                    'src' => '0.0.0.0/0',
                    'state' => 'ESTABLISHED',
                    'target' => 'DROP',
                  },
                  'rule 4' => {
                    'chain' => 'INPUT',
                    'dpt' => '',
                    'dst' => '0.0.0.0/0',
                    'icmptype' => '',
                    'in' => '*',
                    'info' => 'state ESTABLISHED /* 009 accept inbound icmp state established */',
                    'opts' => '--',
                    'out' => '*',
                    'proto' => 'icmp',
                    'spt' => '',
                    'src' => '0.0.0.0/0',
                    'state' => 'ESTABLISHED',
                    'target' => 'ACCEPT',
                  },
                  'rule 5' => {
                    'chain' => 'INPUT',
                    'dpt' => '',
                    'dst' => '0.0.0.0/0',
                    'icmptype' => '',
                    'in' => '*',
                    'info' => 'multiport dports 22 state NEW /* 100 ssh inbound */',
                    'opts' => '--',
                    'out' => '*',
                    'proto' => 'tcp',
                    'spt' => '',
                    'src' => '0.0.0.0/0',
                    'state' => 'NEW',
                    'target' => 'ACCEPT',
                  },
                  'rule 6' => {
                    'chain' => 'INPUT',
                    'dpt' => '',
                    'dst' => '0.0.0.0/0',
                    'icmptype' => '',
                    'in' => '*',
                    'info' => 'multiport dports 443 state NEW /* 101 httpd inbound */',
                    'opts' => '--',
                    'out' => '*',
                    'proto' => 'tcp',
                    'spt' => '',
                    'src' => '0.0.0.0/0',
                    'state' => 'NEW',
                    'target' => 'ACCEPT',
                  },
                  'rule 7' => {
                    'chain' => 'INPUT',
                    'dpt' => '',
                    'dst' => '0.0.0.0/0',
                    'icmptype' => '',
                    'in' => '*',
                    'info' => 'multiport dports 53 state NEW /* 102 dns udp inbound */',
                    'opts' => '--',
                    'out' => '*',
                    'proto' => 'udp',
                    'spt' => '',
                    'src' => '0.0.0.0/0',
                    'state' => 'NEW',
                    'target' => 'ACCEPT',
                  },
                  'rule 8' => {
                    'chain' => 'OUTPUT',
                    'dpt' => '',
                    'dst' => '0.0.0.0/0',
                    'icmptype' => '',
                    'in' => '*',
                    'info' => '/* 002 accept all outgoing traffic to local interface */',
                    'opts' => '--',
                    'out' => 'lo',
                    'proto' => 'all',
                    'spt' => '',
                    'src' => '0.0.0.0/0',
                    'state' => '',
                    'target' => 'ACCEPT',
                  },
                  'rule 9' => {
                    'chain' => 'OUTPUT',
                    'dpt' => '',
                    'dst' => '0.0.0.0/0',
                    'icmptype' => '',
                    'in' => '*',
                    'info' => 'state NEW,ESTABLISHED /* 005 accept outbound udp state new, established */',
                    'opts' => '--',
                    'out' => '*',
                    'proto' => 'udp',
                    'spt' => '',
                    'src' => '0.0.0.0/0',
                    'state' => 'NEW,ESTABLISHED',
                    'target' => 'ACCEPT',
                  },
                },
                'policy_status' => false,
              },
            },
            'network6' => '1.2.3.4',
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
            is_expected.to contain_firewall('004-6 accept outbound tcp state new, established')
              .with(
                'chain'  => 'OUTPUT',
                'proto'  => 'tcp',
                'state'  => ['NEW', 'ESTABLISHED'],
                'jump' => 'ACCEPT',
                'provider' => 'ip6tables',
              )

            is_expected.to contain_firewall('005-6 accept outbound udp state new, established')
              .with(
                'chain'  => 'OUTPUT',
                'proto'  => 'udp',
                'state'  => ['NEW', 'ESTABLISHED'],
                'jump' => 'ACCEPT',
                'provider' => 'ip6tables',
              )

            is_expected.to contain_firewall('006-6 accept outbound icmp state new, established')
              .with(
                'chain'  => 'OUTPUT',
                'proto'  => 'icmp',
                'state'  => ['NEW', 'ESTABLISHED'],
                'jump' => 'ACCEPT',
                'provider' => 'ip6tables',
              )

            is_expected.to contain_firewall('007-6 accept inbound tcp state established')
              .with(
                'chain'  => 'INPUT',
                'proto'  => 'tcp',
                'state'  => 'ESTABLISHED',
                'jump' => 'ACCEPT',
                'provider' => 'ip6tables',
              )

            is_expected.to contain_firewall('008-6 accept inbound udp state established')
              .with(
                'chain'  => 'INPUT',
                'proto'  => 'udp',
                'state'  => 'ESTABLISHED',
                'jump' => 'ACCEPT',
                'provider' => 'ip6tables',
              )

            is_expected.to contain_firewall('009-6 accept inbound icmp state established')
              .with(
                'chain'  => 'INPUT',
                'proto'  => 'icmp',
                'state'  => 'ESTABLISHED',
                'jump' => 'ACCEPT',
                'provider' => 'ip6tables',
              )
          else
            is_expected.not_to contain_firewall('004-6 accept outbound tcp state new, established')
            is_expected.not_to contain_firewall('005-6 accept outbound udp state new, established')
            is_expected.not_to contain_firewall('006-6 accept outbound icmp state new, established')
            is_expected.not_to contain_firewall('007-6 accept inbound tcp state established')
            is_expected.not_to contain_firewall('008-6 accept inbound udp state established')
            is_expected.not_to contain_firewall('009-6 accept inbound icmp state established')
          end
        }
      end
    end
  end
end
