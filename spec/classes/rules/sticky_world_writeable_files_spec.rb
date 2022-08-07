# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::sticky_world_writeable_files' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        let(:facts) { os_facts }

        it {
          is_expected.to compile
        }
      end
    end
  end
end
