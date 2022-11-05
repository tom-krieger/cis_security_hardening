# frozen_string_literal: true

require 'spec_helper'
require 'pp'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::fapolicyd_policy' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            mountpoints: {
              '/' => {
                'available' => '3.05 GiB',
                'available_bytes' => 3_272_163_328,
                'capacity' => '12.15%',
                'device' => '/dev/mapper/vgos-lvol_root',
                'filesystem' => 'ext4',
                'options' => [ 'rw', 'relatime', 'errors=remount-ro' ],
                'size' => '3.68 GiB',
                'size_bytes' => 3_946_258_432,
                'used' => '431.67 MiB',
                'used_bytes' => 452_636_672
              },
              '/boot' => {
                'available' => '801.44 MiB',
                'available_bytes' => 840_368_128,
                'capacity' => '10.42%',
                'device' => '/dev/sda1',
                'filesystem' => 'ext3',
                'options' => [ 'rw', 'relatime' ],
                'size' => '943.48 MiB',
                'size_bytes' => 989_306_880,
                'used' => '93.24 MiB',
                'used_bytes' => 97_771_520
              },
              '/boot/efi' => {
                'available' => '236.85 MiB',
                'available_bytes' => 248_354_304,
                'capacity' => '1.41%',
                'device' => '/dev/sda2',
                'filesystem' => 'vfat',
                'options' => [ 'rw', 'relatime', 'fmask=0077', 'dmask=0077', 'codepage=437', 'iocharset=ascii', 'shortname=mixed', 'utf8', 'errors=remount-ro' ],
                'size' => '240.23 MiB',
                'size_bytes' => 251_899_904,
                'used' => '3.38 MiB',
                'used_bytes' => 3_545_600
              },
              '/dev' => {
                'available' => '976.79 MiB',
                'available_bytes' => 1_024_233_472,
                'capacity' => '0%',
                'device' => 'udev',
                'filesystem' => 'devtmpfs',
                'options' => [ 'rw', 'nosuid', 'relatime', 'size=1000228k', 'nr_inodes=250057', 'mode=755' ],
                'size' => '976.79 MiB',
                'size_bytes' => 1_024_233_472,
                'used' => '0 bytes',
                'used_bytes' => 0
              },
              '/dev/hugepages' => {
                'available' => '0 bytes',
                'available_bytes' => 0,
                'capacity' => '100%',
                'device' => 'hugetlbfs',
                'filesystem' => 'hugetlbfs',
                'options' => [ 'rw', 'relatime', 'pagesize=2M' ],
                'size' => '0 bytes',
                'size_bytes' => 0,
                'used' => '0 bytes',
                'used_bytes' => 0
              },
              '/dev/mqueue' => {
                'available' => '0 bytes',
                'available_bytes' => 0,
                'capacity' => '100%',
                'device' => 'mqueue',
                'filesystem' => 'mqueue',
                'options' => [ 'rw', 'relatime' ],
                'size' => '0 bytes',
                'size_bytes' => 0,
                'used' => '0 bytes',
                'used_bytes' => 0
              },
              '/dev/pts' => {
                'available' => '0 bytes',
                'available_bytes' => 0,
                'capacity' => '100%',
                'device' => 'devpts',
                'filesystem' => 'devpts',
                'options' => [ 'rw', 'nosuid', 'noexec', 'relatime', 'gid=5', 'mode=620', 'ptmxmode=000' ],
                'size' => '0 bytes',
                'size_bytes' => 0,
                'used' => '0 bytes',
                'used_bytes' => 0
              },
              '/dev/shm' => {
                'available' => '997.32 MiB',
                'available_bytes' => 1_045_762_048,
                'capacity' => '0%',
                'device' => 'tmpfs',
                'filesystem' => 'tmpfs',
                'options' => [ 'rw', 'nosuid', 'nodev', 'noexec' ],
                'size' => '997.32 MiB',
                'size_bytes' => 1_045_762_048,
                'used' => '0 bytes',
                'used_bytes' => 0
              },
              '/home' => {
                'available' => '1.72 GiB',
                'available_bytes' => 1_844_293_632,
                'capacity' => '0.63%',
                'device' => '/dev/mapper/vgos-lvol_home',
                'filesystem' => 'ext4',
                'options' => [ 'rw', 'nodev', 'relatime' ],
                'size' => '1.84 GiB',
                'size_bytes' => 1_975_132_160,
                'used' => '11.18 MiB',
                'used_bytes' => 11_722_752
              },
              '/run' => {
                'available' => '198.52 MiB',
                'available_bytes' => 208_162_816,
                'capacity' => '0.47%',
                'device' => 'tmpfs',
                'filesystem' => 'tmpfs',
                'options' => [ 'rw', 'nosuid', 'noexec', 'relatime', 'size=204252k', 'mode=755' ],
                'size' => '199.46 MiB',
                'size_bytes' => 209_154_048,
                'used' => '968.00 KiB',
                'used_bytes' => 991_232
              },
              '/run/lock' => {
                'available' => '5.00 MiB',
                'available_bytes' => 5_242_880,
                'capacity' => '0%',
                'device' => 'tmpfs',
                'filesystem' => 'tmpfs',
                'options' => [ 'rw', 'nosuid', 'nodev', 'noexec', 'relatime', 'size=5120k' ],
                'size' => '5.00 MiB',
                'size_bytes' => 5_242_880,
                'used' => '0 bytes',
                'used_bytes' => 0
              },
              '/sys/fs/cgroup' => {
                'available' => '997.32 MiB',
                'available_bytes' => 1_045_762_048,
                'capacity' => '0%',
                'device' => 'tmpfs',
                'filesystem' => 'tmpfs',
                'options' => [ 'ro', 'nosuid', 'nodev', 'noexec', 'mode=755' ],
                'size' => '997.32 MiB',
                'size_bytes' => 1_045_762_048,
                'used' => '0 bytes',
                'used_bytes' => 0
              },
              '/tmp' => {
                'available' => '997.32 MiB',
                'available_bytes' => 1_045_762_048,
                'capacity' => '0%',
                'device' => 'tmpfs',
                'filesystem' => 'tmpfs',
                'options' => [ 'rw', 'nosuid', 'nodev', 'noexec' ],
                'size' => '997.32 MiB',
                'size_bytes' => 1_045_762_048,
                'used' => '0 bytes',
                'used_bytes' => 0
              },
              '/usr' => {
                'available' => '3.04 GiB',
                'available_bytes' => 3_266_240_512,
                'capacity' => '56.64%',
                'device' => '/dev/mapper/vgos-lvol_usr',
                'filesystem' => 'ext4',
                'options' => [ 'rw', 'relatime' ],
                'size' => '7.41 GiB',
                'size_bytes' => 7_959_814_144,
                'used' => '3.97 GiB',
                'used_bytes' => 4_267_225_088
              },
              '/var' => {
                'available' => '8.26 GiB',
                'available_bytes' => 8_863_764_480,
                'capacity' => '6.14%',
                'device' => '/dev/mapper/vgos-lvol_var',
                'filesystem' => 'ext4',
                'options' => [ 'rw', 'relatime' ],
                'size' => '9.29 GiB',
                'size_bytes' => 9_972_477_952,
                'used' => '553.15 MiB',
                'used_bytes' => 580_022_272
              },
              '/var/log' => {
                'available' => '8.73 GiB',
                'available_bytes' => 9_373_147_136,
                'capacity' => '0.75%',
                'device' => '/dev/mapper/vgos-lvol_var_log',
                'filesystem' => 'ext4',
                'options' => [ 'rw', 'relatime' ],
                'size' => '9.29 GiB',
                'size_bytes' => 9_972_477_952,
                'used' => '67.37 MiB',
                'used_bytes' => 70_639_616
              },
              '/var/log/audit' => {
                'available' => '8.79 GiB',
                'available_bytes' => 9_438_425_088,
                'capacity' => '0.06%',
                'device' => '/dev/mapper/vgos-lvol_var_log_audit',
                'filesystem' => 'ext4',
                'options' => [ 'rw', 'relatime' ],
                'size' => '9.29 GiB',
                'size_bytes' => 9_972_477_952,
                'used' => '5.11 MiB',
                'used_bytes' => 5_361_664
              },
              '/var/tmp' => {
                'available' => '1.73 GiB',
                'available_bytes' => 1_855_975_424,
                'capacity' => '0.00%',
                'device' => '/dev/mapper/vgos-lvol_var_tmp',
                'filesystem' => 'ext4',
                'options' => [ 'rw', 'nosuid', 'nodev', 'noexec', 'relatime' ],
                'size' => '1.84 GiB',
                'size_bytes' => 1_975_132_160,
                'used' => '40.00 KiB',
                'used_bytes' => 40_960
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
            'permissive' => '1',
            'create_rules' => true,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('fapolicyd_permissive')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/fapolicyd/fapolicyd.conf',
                'match'              => '^permissive =',
                'line'               => 'permissive = 1',
                'append_on_no_match' => true,
              )
            is_expected.to contain_concat('/etc/fapolicyd/fapolicyd.mounts')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )

            os_facts[:mountpoints].each do |mp, data|
              next unless (['tmpfs', 'ext4', 'ext3', 'xfs'].include? data['filesystem']) && (mp !~ %r{^/run}) && (mp !~ %r{/sys})
              is_expected.to contain_concat__fragment("mount-#{mp}")
                .with(
                  'content' => "#{mp}\n",
                  'target'  => '/etc/fapolicyd/fapolicyd.mounts',
                )
            end
          else
            is_expected.not_to contain_file_line('fapolicyd_permissive')
            is_expected.not_to contain_concat('/etc/fapolicyd/fapolicyd.mounts')
          end
        }
      end
    end
  end
end
