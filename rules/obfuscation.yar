rule hex_obfuscation {
    meta:
        description = "Detects hex-encoded strings used for obfuscation"
        author = "AEGIS"
        severity = "high"

    strings:
        $hex_chain = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}/

    condition:
        $hex_chain
}

rule base64_payload {
    meta:
        description = "Detects base64-encoded payloads"
        author = "AEGIS"
        severity = "medium"

    strings:
        $b64_decode_exec = /base64\.b64decode\s*\([^)]+\).*exec/
        $atob_eval = /atob\s*\([^)]+\).*eval/

    condition:
        any of them
}

rule chr_chain {
    meta:
        description = "Detects chr() chains used for string obfuscation"
        author = "AEGIS"
        severity = "high"

    strings:
        $chr_py = /chr\(\d+\)\s*\+\s*chr\(\d+\)(\s*\+\s*chr\(\d+\)){3,}/
        $char_js = /String\.fromCharCode\(\d+(,\s*\d+){5,}\)/

    condition:
        any of them
}
