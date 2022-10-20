control "SV-216023" do
  title "The audit system must be configured to audit file deletions."
  desc "Without auditing, malicious activity cannot be detected."
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
|cut -f2 -d=

If \"fd\" audit flag is not included in output, this is a finding.

For Solaris 
11.4 or newer:
# pfexec auditconfig -t -getflags | cut -f2 -d=

If \"fd\" audit flag is not 
included in output, this is a finding.

Determine if auditing policy is set to collect 
command line arguments.

# pfexec auditconfig -getpolicy | grep active | grep argv

If the 
active audit policies line does not appear, this is a finding."
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
  tag gid: "V-216023"
  tag rid: "SV-216023r603268_rule"
  tag stig_id: "SOL-11.1-010220"
  tag fix_id: "F-17259r372452_fix"
  tag legacy: ["SV-60681","V-47805"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]

  uname = command("uname –v").stdout.strip.split(".0.").collect(&:strip)[0]
  audit_flag1 = command("pfexec auditconfig -getflags | grep active | cut -f2 -d=").stdout.strip
  audit_flag2 = command("pfexec auditconfig -t -getflags | cut -f2 -d=").stdout.strip
  audit_condition_value = command("pfexec auditconfig -getpolicy | grep active | grep argv").stdout.strip.split("=").collect(&:strip)[1]
  old_flags = input('old_audit_flags')
  new_flags = input('new_audit_flags')
  
  unless command('zonename').stdout.strip == "global"
    impact 0.0
    describe 'This control is Not Applicable. This control applies to the global zone only.' do
      skip 'This control is Not Applicable. This control applies to the global zone only.' 
    end
  else
    if uname == "11.1" || "11.2" || "11.3" 
      describe audit_flag1 do
        old_flags.each do |flag|
          it { should include flag}
        end
      end
    elsif uname == "11.4"
      describe audit_flag2 do
        new_flags.each do |sol_flag|
          it { should include sol_flag}
        end
      end
    end
  end
  describe audit_condition_value do
    it { should_not cmp ''}
  end
end
