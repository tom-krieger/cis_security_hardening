# frozen_string_literal: true

require 'spec_helper'
require 'pp'

mpts = ['/dev/shm', '/home', '/tmp', '/var/tmp', '/var', '/var/log', '/var/log/audit']
opts = ['nodev', 'noexec', 'nosuid', 'usrquota', 'grpquota', 'quota']

mpts.each do |mpt|
  opts.each do |opt|
    describe 'cis_security_hardening::set_mount_options' do
      on_supported_os.each do |os, os_facts|
        context "on #{os}, with #{mpt}, #{opt}" do
          let(:title) { "#{mpt}-#{opt}" }
          let(:params) do
            {
              'mountpoint'   => mpt.to_s,
              'mountoptions' => opt.to_s,
            }
          end
          let(:facts) { os_facts }

          it {
            is_expected.to compile
            aug = "/etc/fstab - work on #{mpt} with #{opt}"
            exc = "Exec[remount #{mpt} with #{opt}]"
            is_expected.to contain_augeas(aug)
              .with(
                'context' => '/files/etc/fstab',
                'changes' => [
                  "ins opt after /files/etc/fstab/*[file = '#{mpt}']/opt[last()]",
                  "set *[file = '#{mpt}']/opt[last()] #{opt}",
                ],
                'onlyif' => "match *[file = '#{mpt}']/opt[. = '#{opt}'] size == 0",
              )
              .that_notifies(exc)

            is_expected.to contain_exec("remount #{mpt} with #{opt}")
              .with(
                'command'     => "mount -o remount #{mpt}",
                'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'refreshonly' => true,
              )
          }
        end

        context "on #{os}, with #{mpt}, #{opt} with invalid mountpoint" do
          let(:title) { "#{mpt}-#{opt}" }
          let(:params) do
            {
              'mountpoint'   => 'rm -rf / ; /dev/shm',
              'mountoptions' => opt.to_s,
            }
          end
          let(:facts) { os_facts }

          it {
            is_expected.to compile.and_raise_error(%r{Cis_security_hardening::Mountpoint})
          }
        end

        context "on #{os}, with #{mpt}, #{opt} with invalid mountoptions" do
          let(:title) { "#{mpt}-#{opt}" }
          let(:params) do
            {
              'mountpoint'   => mpt.to_s,
              'mountoptions' => 'rm -rf /;nodev',
            }
          end
          let(:facts) { os_facts }

          it {
            is_expected.to compile.and_raise_error(%r{expects a match for Cis_security_hardening::Mountoption})
          }
        end
      end
    end
  end
end
