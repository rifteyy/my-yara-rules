rule Detect_Quick_Batch_File_Protector
{
    meta:
        description = "Detects files compiled by Quick Batch File Compiler (QuickBFC/QBFC)"
        author = "rifteyy"
        date = "2026-02-09"
        reference = "https://www.abyssmedia.com/quickbfc/"
        hash = "c1a55fbb7a53a5a4d60fe7d8f75edfce331900d8a94854fd566cfef9433ac181"
        severity = "Low"

    strings:
        $str1 = "In order to correctly identify malware while avoiding false positives" ascii wide
        $str2 = "Encrypted user script: Resource Name: SCRIPT, Resource Type: RC DATA" ascii wide
        $str3 = "Please contact us for more details: support@abyssmedia.com" ascii wide
        $str4 = "executable file generated in the Trial Version cannot be run on another computer" ascii wide
        $str5 = "This file has been created by the trial version of Quick Batch File Compiler." ascii wide
        $str6 = "Could not create process.}Quick Batch File Compiler Runtime Module Version" ascii wide
        $str7 = /Copyright \(C\) 2004-.... Abyss Media Company, https:\/\/www\.abyssmedia\.com/ ascii wide

    condition:
        any of ($str*)
}
