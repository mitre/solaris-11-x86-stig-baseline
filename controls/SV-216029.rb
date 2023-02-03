control "SV-216029" do
  title "The audit system must be configured to audit all administrative, privileged, and security 
actions."
  desc "Without auditing, individual system accesses cannot be tracked, and malicious activity 
cannot be detected and traced back to an individual account."
  desc "check", "The Audit Configuration profile is required.

This check applies to the global zone only. 
Determine the zone that you are currently securing.

# zonename

If the command output is 
\"global\", this check applies.

Determine the OS version you are currently securing.
# 
uname –v

For Solaris 11, 11.1, 11.2, and 11.3:
# pfexec auditconfig -getflags | grep active 
| cut -f2 -d=

If \"as\" audit flag is not included in output, this is a finding.

For Solaris 
11.4 or newer:
# pfexec auditconfig -t -getflags | cut -f2 -d=

If \"cusa\" or if the 
\"ft,lo,ap,ss,as,ua,pe” audit flag(s) are not included in output, this is a 
finding.

Determine if auditing policy is set to collect command line arguments.

# pfexec 
auditconfig -getpolicy | grep active | grep argv

If the active audit policies line does not 
appear, this is a finding."
  desc "fix", "The Audit Configuration profile is required. All audit flags must be enabled in a single 
command.

This action applies to the global zone only. Determine the zone that you are 
currently securing.

# zonename

If the command output is \"global\", this action 
applies.

For Solaris 11, 11.1, 11.2, and 11.3:
# pfexec auditconfig -setflags 
cusa,-ps,fd,-fa,fm

For Solaris 11.4 or newer:
# pfexec auditconfig -setflags 
cusa,-fa,-ex,-ps,fd,fm

Enable the audit policy to collect command line arguments.

# 
pfexec auditconfig -setpolicy +argv

These changes will not affect users that are 
currently logged in."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216029"
  tag rid: "SV-216029r793044_rule"
  tag stig_id: "SOL-11.1-010300"
  tag fix_id: "F-17265r372470_fix"
  tag legacy: ["V-47817","SV-60693"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]

  uname = command("uname -v").stdout.strip.split(".")[1]
  audit_flag = command("pfexec auditconfig -getflags | grep active | cut -f2 -d=").stdout.strip
  audit_condition_value = command("pfexec auditconfig -getpolicy | grep active | grep argv").stdout.strip.split("=").collect(&:strip)[1]
  old_flags = input("old_audit_flags")
  new_flags = input("new_audit_flags")

  if !command("zonename").stdout.strip == "global"
    impact 0.0
    describe "This control is Not Applicable. This control applies to the global zone only." do
      skip "This control is Not Applicable. This control applies to the global zone only."
    end
  elsif audit_flag.include?("sstore")
    describe "The audit system does not have flags set.\n\ The auditconfig command returned: #{audit_flag} .\n\ Review the Fix Text to properly configure this system. " do
      subject {false}
      it {should be_true} 
    end
  else
    case uname
    when 0..3
      describe audit_flag do
        old_flags.each do |flag|
          it { should include flag }
        end
      end
    else
      describe audit_flag do
        new_flags.each do |sol_flag|
          it { should include sol_flag }
        end
      end
    end
    describe audit_condition_value do
      it { should_not be_empty }
    end
  end
end