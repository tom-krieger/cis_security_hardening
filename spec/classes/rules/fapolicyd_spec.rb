# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::fapolicyd' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            mountpoints: {
              "/" => {
                "available" => "3.05 GiB",
                "available_bytes" => 3272163328,
                "capacity" => "12.15%",
                "device" => "/dev/mapper/vgos-lvol_root",
                "filesystem" => "ext4",
                "options" => [ "rw", "relatime", "errors=remount-ro" ],
                "size" => "3.68 GiB",
                "size_bytes" => 3946258432,
                "used" => "431.67 MiB",
                "used_bytes" => 452636672
              },
              "/boot" => {
                "available" => "801.44 MiB",
                "available_bytes" => 840368128,
                "capacity" => "10.42%",
                "device" => "/dev/sda1",
                "filesystem" => "ext3",
                "options" => [ "rw", "relatime" ],
                "size" => "943.48 MiB",
                "size_bytes" => 989306880,
                "used" => "93.24 MiB",
                "used_bytes" => 97771520
              },
              "/boot/efi" => {
                "available" => "236.85 MiB",
                "available_bytes" => 248354304,
                "capacity" => "1.41%",
                "device" => "/dev/sda2",
                "filesystem" => "vfat",
                "options" => [ "rw", "relatime", "fmask=0077", "dmask=0077", "codepage=437", "iocharset=ascii", "shortname=mixed", "utf8", "errors=remount-ro" ],
                "size" => "240.23 MiB",
                "size_bytes" => 251899904,
                "used" => "3.38 MiB",
                "used_bytes" => 3545600
              },
              "/dev" => {
                "available" => "976.79 MiB",
                "available_bytes" => 1024233472,
                "capacity" => "0%",
                "device" => "udev",
                "filesystem" => "devtmpfs",
                "options" => [ "rw", "nosuid", "relatime", "size=1000228k", "nr_inodes=250057", "mode=755" ],
                "size" => "976.79 MiB",
                "size_bytes" => 1024233472,
                "used" => "0 bytes",
                "used_bytes" => 0
              },
              "/dev/hugepages" => {
                "available" => "0 bytes",
                "available_bytes" => 0,
                "capacity" => "100%",
                "device" => "hugetlbfs",
                "filesystem" => "hugetlbfs",
                "options" => [ "rw", "relatime", "pagesize=2M" ],
                "size" => "0 bytes",
                "size_bytes" => 0,
                "used" => "0 bytes",
                "used_bytes" => 0
              },
              "/dev/mqueue" => {
                "available" => "0 bytes",
                "available_bytes" => 0,
                "capacity" => "100%",
                "device" => "mqueue",
                "filesystem" => "mqueue",
                "options" => [ "rw", "relatime" ],
                "size" => "0 bytes",
                "size_bytes" => 0,
                "used" => "0 bytes",
                "used_bytes" => 0
              },
              "/dev/pts" => {
                "available" => "0 bytes",
                "available_bytes" => 0,
                "capacity" => "100%",
                "device" => "devpts",
                "filesystem" => "devpts",
                "options" => [ "rw", "nosuid", "noexec", "relatime", "gid=5", "mode=620", "ptmxmode=000" ],
                "size" => "0 bytes",
                "size_bytes" => 0,
                "used" => "0 bytes",
                "used_bytes" => 0
              },
              "/dev/shm" => {
                "available" => "997.32 MiB",
                "available_bytes" => 1045762048,
                "capacity" => "0%",
                "device" => "tmpfs",
                "filesystem" => "tmpfs",
                "options" => [ "rw", "nosuid", "nodev", "noexec" ],
                "size" => "997.32 MiB",
                "size_bytes" => 1045762048,
                "used" => "0 bytes",
                "used_bytes" => 0
              },
              "/home" => {
                "available" => "1.72 GiB",
                "available_bytes" => 1844293632,
                "capacity" => "0.63%",
                "device" => "/dev/mapper/vgos-lvol_home",
                "filesystem" => "ext4",
                "options" => [ "rw", "nodev", "relatime" ],
                "size" => "1.84 GiB",
                "size_bytes" => 1975132160,
                "used" => "11.18 MiB",
                "used_bytes" => 11722752
              },
              "/run" => {
                "available" => "198.52 MiB",
                "available_bytes" => 208162816,
                "capacity" => "0.47%",
                "device" => "tmpfs",
                "filesystem" => "tmpfs",
                "options" => [ "rw", "nosuid", "noexec", "relatime", "size=204252k", "mode=755" ],
                "size" => "199.46 MiB",
                "size_bytes" => 209154048,
                "used" => "968.00 KiB",
                "used_bytes" => 991232
              },
              "/run/lock" => {
                "available" => "5.00 MiB",
                "available_bytes" => 5242880,
                "capacity" => "0%",
                "device" => "tmpfs",
                "filesystem" => "tmpfs",
                "options" => [ "rw", "nosuid", "nodev", "noexec", "relatime", "size=5120k" ],
                "size" => "5.00 MiB",
                "size_bytes" => 5242880,
                "used" => "0 bytes",
                "used_bytes" => 0
              },
              "/sys/fs/cgroup" => {
                "available" => "997.32 MiB",
                "available_bytes" => 1045762048,
                "capacity" => "0%",
                "device" => "tmpfs",
                "filesystem" => "tmpfs",
                "options" => [ "ro", "nosuid", "nodev", "noexec", "mode=755" ],
                "size" => "997.32 MiB",
                "size_bytes" => 1045762048,
                "used" => "0 bytes",
                "used_bytes" => 0
              },
              "/tmp" => {
                "available" => "997.32 MiB",
                "available_bytes" => 1045762048,
                "capacity" => "0%",
                "device" => "tmpfs",
                "filesystem" => "tmpfs",
                "options" => [ "rw", "nosuid", "nodev", "noexec" ],
                "size" => "997.32 MiB",
                "size_bytes" => 1045762048,
                "used" => "0 bytes",
                "used_bytes" => 0
              },
              "/usr" => {
                "available" => "3.04 GiB",
                "available_bytes" => 3266240512,
                "capacity" => "56.64%",
                "device" => "/dev/mapper/vgos-lvol_usr",
                "filesystem" => "ext4",
                "options" => [ "rw", "relatime" ],
                "size" => "7.41 GiB",
                "size_bytes" => 7959814144,
                "used" => "3.97 GiB",
                "used_bytes" => 4267225088
              },
              "/var" => {
                "available" => "8.26 GiB",
                "available_bytes" => 8863764480,
                "capacity" => "6.14%",
                "device" => "/dev/mapper/vgos-lvol_var",
                "filesystem" => "ext4",
                "options" => [ "rw", "relatime" ],
                "size" => "9.29 GiB",
                "size_bytes" => 9972477952,
                "used" => "553.15 MiB",
                "used_bytes" => 580022272
              },
              "/var/log" => {
                "available" => "8.73 GiB",
                "available_bytes" => 9373147136,
                "capacity" => "0.75%",
                "device" => "/dev/mapper/vgos-lvol_var_log",
                "filesystem" => "ext4",
                "options" => [ "rw", "relatime" ],
                "size" => "9.29 GiB",
                "size_bytes" => 9972477952,
                "used" => "67.37 MiB",
                "used_bytes" => 70639616
              },
              "/var/log/audit" => {
                "available" => "8.79 GiB",
                "available_bytes" => 9438425088,
                "capacity" => "0.06%",
                "device" => "/dev/mapper/vgos-lvol_var_log_audit",
                "filesystem" => "ext4",
                "options" => [ "rw", "relatime" ],
                "size" => "9.29 GiB",
                "size_bytes" => 9972477952,
                "used" => "5.11 MiB",
                "used_bytes" => 5361664
              },
              "/var/tmp" => {
                "available" => "1.73 GiB",
                "available_bytes" => 1855975424,
                "capacity" => "0.00%",
                "device" => "/dev/mapper/vgos-lvol_var_tmp",
                "filesystem" => "ext4",
                "options" => [ "rw", "nosuid", "nodev", "noexec", "relatime" ],
                "size" => "1.84 GiB",
                "size_bytes" => 1975132160,
                "used" => "40.00 KiB",
                "used_bytes" => 40960
              }
            },
            cis_security_hardening: {
              abrt: {
                packages: ['abrt-libs', 'abrt-cli-ng', 'abrt-cli']
              }
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'gid' => 'users',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_package('fapolicyd')
              .with(
                'ensure' => 'installed',
              )

            is_expected.to contain_file('/run/fapolicyd')
              .with(
                'ensure' => 'directory',
                'owner' => 'fapolicyd',
                'group' => 'users',
                'mode' => '0755',
              )
              .that_requires('Package[fapolicyd]')

            is_expected.to contain_file_line('fix fapolicyd gid')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/fapolicyd/fapolicyd.conf',
                'match'              => '^gid = fapolicyd',
                'line'               => 'gid = users',
                'append_on_no_match' => true,
              )
              .that_requires('Package[fapolicyd]')

              os_facts[:mountpoints].each do |mp, data|

                if ['tmpfs', 'ext4', 'ext3', 'xfs'].include? data[:filesystem] && mp !~ /^\/run/ && mp !~ /\/sys/
                  is_expected.to contain_concat__fragment("mount-#{mp}")
                    .with(
                      'content' => "#{mp}\n",
                      'target'  => '/etc/fapolicyd/fapolicyd.mounts',
                    )
                end
              end
          else
            is_expected.not_to contain_package('fapolicyd')
            is_expected.not_to contain_file('/run/fapolicyd')
          end
        }
      end
    end
  end
end
