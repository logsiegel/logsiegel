Output media/social/p6-offline.gif
Set Theme "Catppuccin Mocha"
Set FontSize 22
Set Width 1200
Set Height 460
Set Padding 24
Set TypingSpeed 12ms
Hide
Type `export PATH="$PWD/.venv/bin:$PATH" && cd "$(mktemp -d)" && logsiegel init trail --origin support-agent >/dev/null && logsiegel log trail --event inference --attr amount="250 EUR" --input "refund 250 EUR to customer 4711" --store-payload >/dev/null && logsiegel checkpoint trail >/dev/null && logsiegel receipt trail --seq 0 --out receipt.json >/dev/null && cp trail/keys/signing_key.pub . && clear`
Enter
Show
Hide
Type `mkdir auditor && cp receipt.json signing_key.pub auditor/ && cd auditor && clear`
Enter
Show
Type "ls"
Enter
Sleep 600ms
Type `# no server. no database. no account.`
Enter
Type "logsiegel verify-receipt receipt.json --pubkey signing_key.pub"
Enter
Sleep 3s
