# frozen_string_literal: true

# get uid, gid, and perms of a file

def read_file_stats(filename)
  if File.exist?(filename)
    uid = File.stat(filename).uid
    gid = File.stat(filename).gid
    fmode = File.stat(filename).mode & 0o7777
    combined = "#{uid}-#{gid}-#{fmode}"
    ret = {
      'uid' => uid,
      'gid' => gid,
      'mode' => fmode,
      'combined' => combined,
    }
  else
    ret = {
      'uid' => 'none',
      'gid' => 'none',
      'mode' => 'none',
      'combined' => 'none-none-none',
    }
  end

  ret
end
