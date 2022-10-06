# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::fat' do
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

          if os_facts[:operatingsystem].casecmp('centos').zero? ||
             os_facts[:operatingsystem].casecmp('almalinux').zero? ||
             os_facts[:operatingsystem].casecmp('rocky').zero? ||
             os_facts[:operatingsystem].casecmp('redhat').zero?

            if os_facts[:operatingsystemmajrelease] == '7'

              if enforce
                is_expected.to contain_kmod__install('fat')
                  .with(
                    command: '/bin/true',
                  )
                is_expected.to contain_kmod__install('vfat')
                  .with(
                    command: '/bin/true',
                  )
                is_expected.to contain_kmod__install('msdos')
                  .with(
                    command: '/bin/true',
                  )
              else
                is_expected.not_to contain_kmod__install('fat')
                is_expected.not_to contain_kmod__install('vfat')
                is_expected.not_to contain_kmod__install('msdos')
              end

            elsif os_facts[:operatingsystemmajrelease] == '8'
              if enforce
                is_expected.to contain_kmod__install('vfat')
                  .with(
                    command: '/bin/true',
                  )
              else
                is_expected.not_to contain_kmod__install('vfat')
              end
            end

          elsif os_facts[:operatingsystem].casecmp('ubuntu').zero?

            if enforce
              is_expected.to contain_kmod__install('vfat')
                .with(
                  command: '/bin/true',
                )
              is_expected.not_to contain_kmod__install('fat')
              is_expected.not_to contain_kmod__install('msdos')
            else
              is_expected.not_to contain_kmod__install('vfat')
            end

          elsif os_facts[:operatingsystem].casecmp('sles').zero?
            if enforce
              is_expected.to contain_kmod__install('fat')
                .with(
                  command: '/bin/true',
                )
              is_expected.to contain_kmod__install('vfat')
                .with(
                  command: '/bin/true',
                )
              is_expected.to contain_kmod__install('msdos')
                .with(
                  command: '/bin/true',
                )
            else
              is_expected.not_to contain_kmod__install('fat')
              is_expected.not_to contain_kmod__install('vfat')
              is_expected.not_to contain_kmod__install('msdos')
            end
          end
        }
      end
    end
  end
end
