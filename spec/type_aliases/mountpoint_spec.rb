# frozen_string_literal: true

require 'spec_helper'

describe 'Cis_security_hardening::Mountpoint' do
  describe 'valid handling' do
    [
      '/var',
      '/var/log',
      '/',
      '/home',
    ].each do |value|
      describe value.inspect do
        it { is_expected.to allow_value(value) }
      end
    end
  end

  describe 'invalid path handling' do
    context 'garbage inputs' do
      [
        [nil],
        [nil, nil],
        { 'foo' => 'bar' },
        {},
        '',
        'nodev;/root',
        'cat /etc/shadow;/home',
        '/home;rm -rf /',
      ].each do |value|
        describe value.inspect do
          it { is_expected.not_to allow_value(value) }
        end
      end
    end
  end
end
