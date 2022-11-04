# frozen_string_literal: true

require 'spec_helper'

describe 'Cis_security_hardening::Mountoption' do
  describe 'valid handling' do
    [
      'nodev',
      'noexec',
      'nosuid',
      'defaults',
      'sec=krb5:krb5i:krb5p',
      'size=2G',
      'uid=0',
      'gid=0',
      'fmask=0077'
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
        'nodev;rm -rf /',
        'cat /etc/shadow;nodev',
        'secd=sec=krb5:krb5i:krb5p',
      ].each do |value|
        describe value.inspect do
          it { is_expected.not_to allow_value(value) }
        end
      end
    end
  end
end
