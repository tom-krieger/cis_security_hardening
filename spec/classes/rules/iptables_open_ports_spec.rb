# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::iptables_open_ports' do
  let(:pre_condition) do
    <<-EOF
    exec { 'save iptables rules':
      command    => 'service iptables save',
      path       => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      unless     => 'test -z "$(grep -e AlmaLinux -e Rocky /etc/redhat-release 2>/dev/null)"',
      refreshonly => true,
    }
    EOF
  end

  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            'cis_security_hardening' => {
              'iptables' => {
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
                    'target' => 'DROP',
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
          )
        end

        let(:params) do
          {
            'enforce' => enforce,
            'firewall_rules' => {
              '100 ssh inbound' => {
                'chain' => 'INPUT',
                'proto' => 'tcp',
                'dport' => 22,
                'state' => 'NEW',
                'action' => 'accept',
              },
              '101 httpd inbound' => {
                'chain' => 'INPUT',
                'proto' => 'tcp',
                'dport' => 443,
                'state' => 'NEW',
                'action' => 'accept',
              },
              '102 dns udp inbound' => {
                'chain' => 'INPUT',
                'proto' => 'udp',
                'dport' => 53,
                'state' => 'NEW',
                'action' => 'accept',
              },
              '103 dns udp outbound' => {
                'chain' => 'OUTPUT',
                'proto' => 'udp',
                'dport' => 53,
                'state' => 'NEW',
                'action' => 'accept',
              },
              '104 dns tcp inbound' => {
                'chain' => 'INPUT',
                'proto' => 'tcp',
                'dport' => 53,
                'state' => 'NEW',
                'action' => 'accept',
              },
            },
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_firewall('100 ssh inbound')
              .with(
                'chain'  => 'INPUT',
                'proto'  => 'tcp',
                'dport'  => 22,
                'state'  => 'NEW',
                'action' => 'accept',
              )
            is_expected.to contain_firewall('101 httpd inbound')
              .with(
                'chain'  => 'INPUT',
                'proto'  => 'tcp',
                'dport'  => 443,
                'state'  => 'NEW',
                'action' => 'accept',
              )
            is_expected.to contain_firewall('102 dns udp inbound')
              .with(
                'chain'  => 'INPUT',
                'proto'  => 'udp',
                'dport'  => 53,
                'state'  => 'NEW',
                'action' => 'accept',
              )
            is_expected.to contain_firewall('103 dns udp outbound')
              .with(
                'chain'  => 'OUTPUT',
                'proto'  => 'udp',
                'dport'  => 53,
                'state'  => 'NEW',
                'action' => 'accept',
              )
            is_expected.to contain_firewall('104 dns tcp inbound')
              .with(
                'chain'  => 'INPUT',
                'proto'  => 'tcp',
                'dport'  => 53,
                'state'  => 'NEW',
                'action' => 'accept',
              )
          else
            is_expected.not_to contain_firewall('100 ssh inbound')
            is_expected.not_to contain_firewall('101 httpd inbound')
            is_expected.not_to contain_firewall('102 dns udp inbound')
            is_expected.not_to contain_firewall('103 dns udp outbound')
            is_expected.not_to contain_firewall('104 dns tcp inbound')
          end
        }
      end
    end
  end
end
