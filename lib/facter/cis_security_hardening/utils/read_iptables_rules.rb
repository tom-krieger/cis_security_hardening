# frozen_string_literal: true

def read_iptables_rules(version = '4')
  iptables = {}

  cmd = if version == '4'
          '/sbin/iptables'
        elsif version == '6'
          '/sbin/ip6tables'
        else
          '/i-do-not-exist'
        end
  if File.exist?(cmd)
    lines = Facter::Core::Execution.exec("#{cmd} -L -n -v")
    rules = if lines.nil? || lines.empty?
              []
            else
              lines.split("\n")
            end
    default_policies = {}
    policy = {}
    nr = 0
    chain = ''
    rules.each do |rule|
      next if rule =~ %r{^\s*pkts} || rule =~ %r{^$} || rule =~ %r{^#}
      next if rule.nil?
      m = rule.match(%r{^Chain\s*(?<chain>\w*)\s*\(policy\s*(?<policy>\w*).*\)})
      if m.nil?
        m = rule.match(%r{^Chain\s*(?<chain>\w*)})
        unless m.nil?
          chain = m[:chain]
        end
      else
        chain = m[:chain]
        def_policy = m[:policy]
        default_policies[chain] = def_policy
      end

      m = rule.match(%r{(?<pkts>\d+)\s*(?<bytes>\d+)\s*(?<target>\w*)\s*(?<prot>\w*)\s*(?<opt>[0-9a-zA-Z\-_\.]*)\s*(?<in>[a-zA-Z0-9\*_\-]*)
                        \s*(?<out>[a-zA-Z0-9\*_\-]*)\s*(?<source>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[\/\d+]*)\s*(?<dest>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[\/\d+]*)\s*(?<info>.*)}x)
      next if m.nil?
      nr += 1
      policy["rule #{nr}"] = {}
      policy["rule #{nr}"]['chain'] = chain
      policy["rule #{nr}"]['target'] = m[:target]
      policy["rule #{nr}"]['proto'] = m[:prot]
      policy["rule #{nr}"]['opts'] = m[:opt]
      policy["rule #{nr}"]['src'] = m[:source]
      policy["rule #{nr}"]['dst'] = m[:dest]
      policy["rule #{nr}"]['in'] = m[:in]
      policy["rule #{nr}"]['out'] = m[:out]
      info = m[:info]
      policy["rule #{nr}"]['info'] = info

      m = info.match(%r{(?<proto>[tcp|udp])\s*spt:(?<spt>\d*)})
      if m.nil?
        m = info.match(%r{sports\s*(?<spt>[0-9\,]*)})
        spt = if m.nil?
                ''
              else
                (m[:spt]).to_s
              end
      else
        spt = (m[:spt]).to_s
      end

      m = info.match(%r{(?<proto>[tcp|udp]*)\s*dpt:(?<dpt>\d*)})
      if m.nil?
        m = info.match(%r{dports\s*(?<dpt>[0-9\,]*)})
        dpt = if m.nil?
                ''
              else
                (m[:dpt]).to_s
              end
      else
        dpt = (m[:dpt]).to_s
      end

      m = info.match(%r{state\s*(?<state>[a-zA-Z0-9_\-\,]*)})
      state = if m.nil?
                ''
              else
                m[:state]
              end

      m = info.match(%r{icmptype\s*(?<icmptype>\d+)})
      icmptype = if m.nil?
                   ''
                 else
                   m[:icmptype]
                 end

      policy["rule #{nr}"]['spt'] = spt
      policy["rule #{nr}"]['dpt'] = dpt
      policy["rule #{nr}"]['state'] = state
      policy["rule #{nr}"]['icmptype'] = icmptype
    end
    input_policy = if default_policies.include? 'INPUT'
                     default_policies['INPUT']
                   else
                     'none'
                   end
    output_policy = if default_policies.include? 'OUTPUT'
                      default_policies['OUTPUT']
                    else
                      'none'
                    end
    forward_policy = if default_policies.include? 'FORWARD'
                       default_policies['FORWARD']
                     else
                       'none'
                     end
    iptables['policy_status'] = input_policy.casecmp('drop').zero? && output_policy.casecmp('drop').zero? && forward_policy.casecmp('drop').zero?
    iptables['default_policies'] = default_policies
    iptables['policy'] = policy
  end

  iptables
end
