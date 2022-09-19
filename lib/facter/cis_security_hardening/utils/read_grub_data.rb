# frozen_string_literal: true

def read__data
  grub = {}
  lines = Facter::Core::Execution.exec('grep /boot /etc/mtab').split("\n")
  boot_part = ''
  uuid = ''
  mp = ''
  dev = ''

  lines.each do |line|
    data = line.split("\s")
    dev = data[0]
    mp = data[1]
    val = Facter::Core::Execution.exec("blkid #{dev}").split("\n")
    data = val.split("\s")
    uuid = data[1]
  end

  grub['boot_mountpoint'] = mp
  grub['boot_device'] = dev
  grub['boot_part'] = boot_part
  grub['boot_part_uuid'] = uuid

  grub
end
