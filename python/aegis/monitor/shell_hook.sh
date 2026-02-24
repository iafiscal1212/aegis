#!/bin/bash
# AEGIS Shell Hook — intercepts package install commands
# Source this file in your .bashrc or .zshrc:
#   source ~/.aegis/shell_hook.sh

aegis_pip() {
    if command -v aegis &>/dev/null; then
        aegis check pip "$@" && command pip "$@"
    else
        command pip "$@"
    fi
}

aegis_pip3() {
    if command -v aegis &>/dev/null; then
        aegis check pip3 "$@" && command pip3 "$@"
    else
        command pip3 "$@"
    fi
}

aegis_npm() {
    if command -v aegis &>/dev/null; then
        aegis check npm "$@" && command npm "$@"
    else
        command npm "$@"
    fi
}

aegis_yarn() {
    if command -v aegis &>/dev/null; then
        aegis check yarn "$@" && command yarn "$@"
    else
        command yarn "$@"
    fi
}

aegis_cargo() {
    if command -v aegis &>/dev/null; then
        aegis check cargo "$@" && command cargo "$@"
    else
        command cargo "$@"
    fi
}

alias pip='aegis_pip'
alias pip3='aegis_pip3'
alias npm='aegis_npm'
alias yarn='aegis_yarn'
alias cargo='aegis_cargo'

# Indicate AEGIS is active
if command -v aegis &>/dev/null; then
    echo "[AEGIS] Shell hooks active. Package installs are protected."
fi
