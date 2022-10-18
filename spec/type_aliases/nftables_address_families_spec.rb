# frozen_string_literal: true

require 'spec_helper'

describe 'Cis_security_hardening::Nftables_address_families' do
  describe 'valid handling' do
    [
      'ip',
      'ip6',
      'inet',
      'arp',
      'bridge',
      'netdev',
    ].each do |value|
      describe value.inspect do
        it { is_expected.to allow_value(value) }
      end
    end
  end

  describe 'invalid phandling' do
    context 'garbage inputs' do
      [
        [nil],
        [nil, nil],
        { 'foo' => 'bar' },
        {},
        '',
        'default',
      ].each do |value|
        describe value.inspect do
          it { is_expected.not_to allow_value(value) }
        end
      end
    end
  end
end
