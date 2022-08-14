# frozen_string_literal: true

# use_pkcs11_module = opensc;
def read_pam_pkcs11_conf
  ret = {}
  if File.exist?('/etc/pam_pkcs11/pam_pkcs11.conf')
    val = Facter::Core::Execution.exec('grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf')
    ret['module'] = if val.nil? || val.empty?
                      ''
                    else
                      mod = val.match(%r{use_pkcs11_module\s*=\s*(?<module>.*);})
                      if mod.nil? || mod.empty?
                        ''
                      else
                        mod[:module]
                      end
                    end

    parse = false
    policy = ''
    lines = File.readlines('/etc/pam_pkcs11/pam_pkcs11.conf')
    lines.each do |line|
      if %r{pkcs11_module #{ret['module']} \{}.match?(line)
        parse = true
      end
      if parse
        m = rule.match(%r{cert_policy\s*=\s*(?<policy>.*);})
        unless m.nil?
          policy = m[:policy]
          next
        end
      end
      if parse && line =~ %r{\}$}
        parse = false
      end
    end

    ret['policy'] = policy
  end

  ret
end
