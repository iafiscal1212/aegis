rule dns_exfiltration {
    meta:
        description = "Detects potential DNS-based data exfiltration"
        author = "AEGIS"
        severity = "critical"

    strings:
        $dns_resolve = /socket\.getaddrinfo\s*\(/
        $dns_query = /dns\.resolver\.(query|resolve)\s*\(/
        $subprocess_nslookup = /subprocess.*nslookup/
        $subprocess_dig = /subprocess.*\bdig\b/

    condition:
        any of them
}

rule reverse_shell {
    meta:
        description = "Detects reverse shell patterns"
        author = "AEGIS"
        severity = "critical"

    strings:
        $bash_reverse = /\/bin\/(ba)?sh\s+-i/
        $nc_reverse = /\bnc\s+-[elp]/
        $python_reverse = /socket\.connect\s*\(\s*\(/
        $perl_reverse = /perl.*-e.*socket/

    condition:
        any of them
}

rule crypto_miner {
    meta:
        description = "Detects cryptocurrency mining indicators"
        author = "AEGIS"
        severity = "critical"

    strings:
        $stratum = "stratum+tcp" nocase
        $mining_pool = "mining.pool" nocase
        $coinhive = "coinhive" nocase
        $xmrig = "xmrig" nocase
        $cryptonight = "cryptonight" nocase

    condition:
        any of them
}
