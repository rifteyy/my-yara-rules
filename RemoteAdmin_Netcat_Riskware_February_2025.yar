rule RemoteAdmin_Netcat_Riskware
{
	meta:
		description = "Detects compiled NetCat variant used by malware"
		author = "rifteyy"
		date = "2026-02-19"
		hash1 = "0516064eaa551b5fe047ca39b9e7ca6f7f7ee6d2dcfa0135bd88bb671821b708"
		severity = "Medium"
		
	strings:
		$string1 = "Failed to create shell stdin pipe" ascii wide
		$string2 = "Failed to create shell stdout pipe" ascii wide
		$string3 = "Can't parse %s as an IP address" ascii wide
		$string4 = "[v1.11 NT www.vulnwatch.org/netcat/]" ascii wide
		
	condition:
		uint16(0) == 0x5A4D and
		all of ($string*)
}
