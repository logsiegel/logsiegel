Output media/social/p2-tamper.gif
Set Theme "Catppuccin Mocha"
Set FontSize 22
Set Width 1200
Set Height 500
Set Padding 24
Set TypingSpeed 12ms
Hide
Type `export PATH="$PWD/.venv/bin:$PATH" && cd "$(mktemp -d)" && logsiegel init trail --origin support-agent >/dev/null && logsiegel log trail --event inference --attr amount="250 EUR" --input "refund 250 EUR to customer 4711" --store-payload >/dev/null && logsiegel checkpoint trail >/dev/null && logsiegel receipt trail --seq 0 --out receipt.json >/dev/null && cp trail/keys/signing_key.pub . && clear`
Enter
Show
Type "logsiegel verify trail"
Enter
Sleep 800ms
Type `# one quiet edit. one character.`
Enter
Type `sed -i '' 's/250 EUR/950 EUR/' trail/log.jsonl`
Enter
Sleep 500ms
Type "logsiegel verify trail"
Enter
Sleep 3s
