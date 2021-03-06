control "SV-216214" do
  title "The kernel core dump data directory must be owned by root."
  desc "Kernel core dumps may contain the full contents of system memory at the time of the crash. As the 
system memory may contain sensitive information, it must be protected accordingly. If the 
kernel core dump data directory is not owned by root, the core dumps contained in the directory 
may be subject to unauthorized access."
  desc "check", "The root role is required.

This check applies to the global zone only. Determine the zone 
that you are currently securing.

# zonename

If the command output is \"global\", this check 
applies.

Determine the location of the system dump directory.

# dumpadm | grep 
directory

Check the ownership of the kernel core dump data directory.
# ls -ld [savecore 
directory]

If the kernel core dump data directory is not owned by root, this is a finding. 


In Solaris 11, /var/crash is linked to /var/share/crash."
  desc "fix", "The root role is required.

This action applies to the global zone only. Determine the zone 
that you are currently securing.

# zonename

If the command output is \"global\", this 
action applies.

Determine the location of the system dump directory.

# dumpadm | grep 
directory

Change the owner of the kernel core dump data directory to root.

# chown root 
[savecore directory]

In Solaris 11, /var/crash is linked to /var/share/crash."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216214"
  tag rid: "SV-216214r603268_rule"
  tag stig_id: "SOL-11.1-080090"
  tag fix_id: "F-17450r373025_fix"
  tag legacy: ["V-48011","SV-60883"]
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]
end