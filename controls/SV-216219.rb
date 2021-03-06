control "SV-216219" do
  title "The operating system must implement transaction recovery for transaction-based systems."
  desc "Recovery and reconstitution constitutes executing an operating system contingency plan 
comprised of activities to restore essential missions and business functions. 


Transaction rollback and transaction journaling are examples of mechanisms supporting 
transaction recovery.

While this is typically a database function, operating systems 
could be transactional in nature with respect to file processing."
  desc "check", "Solaris 11 ZFS copy-on-write model allows filesystem accesses to work according to a 
transactional model, such that on-disk content is always consistent and cannot be 
configured to be out of compliance.

Determine if any UFS file systems are mounted with the 
\"nologging\" option.

# mount|grep nologging

If any file systems are listed, this is a 
finding."
  desc "fix", "The root role is required.

Solaris 11 ZFS copy-on-write model allows filesystem accesses 
to work according to a transactional model, such that on-disk content is always consistent 
and cannot be configured to be out of compliance.

If any UFS file systems are mounted with the 
\"nologging\" options, remove that option from the /etc/vfstab file.

# pfedit 
/etc/vfstab

Locate any file systems listed with the \"nologging\" option and delete the 
keyword \"nologging\"."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-216219"
  tag rid: "SV-216219r603268_rule"
  tag stig_id: "SOL-11.1-080150"
  tag fix_id: "F-17455r373040_fix"
  tag legacy: ["SV-60869","V-47997"]
  tag cci: ["CCI-000366","CCI-000553"]
  tag nist: ["CM-6 b","CP-10 (2)"]
end