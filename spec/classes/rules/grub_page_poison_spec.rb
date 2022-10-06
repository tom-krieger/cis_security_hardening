# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::grub_page_poison' do
  let(:pre_condition) do
    <<-EOF
    exec { 'grub2-mkconfig':
      command     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
    EOF
  end

  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_kernel_parameter('page_poison')
              .with(
                'value' => '1',
              )
              .that_notifies('Exec[grub2-mkconfig]')
          else
            is_expected.not_to contain_kernel_parameter('page_poison')
          end
        }
      end
    end
  end
end
