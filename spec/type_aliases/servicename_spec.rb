# frozen_string_literal: true

require 'spec_helper'

describe 'Cis_security_hardening::Servicename' do
  describe 'valid handling' do
    [
      'httpd',
      'sshd',
      'systemd-journal',
      'networking',
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
        'nodev;rm -rf /',
        'cat /etc/shadow;nodev',
      ].each do |value|
        describe value.inspect do
          it { is_expected.not_to allow_value(value) }
        end
      end
    end
  end
end
