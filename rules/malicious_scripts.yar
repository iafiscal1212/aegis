rule malicious_setup_py {
    meta:
        description = "Detects suspicious patterns in Python setup scripts"
        author = "AEGIS"
        severity = "high"

    strings:
        $exec = /exec\s*\(/ nocase
        $eval = /eval\s*\(/ nocase
        $subprocess = /subprocess\.(call|run|Popen)\s*\(/ nocase
        $os_system = /os\.(system|popen)\s*\(/ nocase
        $base64_decode = /base64\.b64decode\s*\(/ nocase
        $import_os = "import os" nocase
        $import_subprocess = "import subprocess" nocase

    condition:
        ($exec or $eval) and ($subprocess or $os_system or $base64_decode)
}

rule credential_theft {
    meta:
        description = "Detects attempts to read credential files"
        author = "AEGIS"
        severity = "critical"

    strings:
        $ssh_key = ".ssh/id_rsa"
        $ssh_ed = ".ssh/id_ed25519"
        $aws_creds = ".aws/credentials"
        $npmrc = ".npmrc"
        $pypirc = ".pypirc"
        $env = ".env"
        $gitconfig = ".git/config"

    condition:
        any of them
}

rule network_callback {
    meta:
        description = "Detects network callbacks to suspicious destinations"
        author = "AEGIS"
        severity = "high"

    strings:
        $ip_url = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $discord_webhook = "discord.com/api/webhooks" nocase
        $telegram_bot = "api.telegram.org/bot" nocase
        $ngrok = "ngrok.io" nocase

    condition:
        any of them
}
