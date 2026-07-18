Output media/social/p5-shred.gif
Set Theme "Catppuccin Mocha"
Set FontSize 20
Set Width 1200
Set Height 620
Set Padding 24
Set TypingSpeed 12ms
Hide
Type `export PATH="$PWD/.venv/bin:$PATH" && cd "$(mktemp -d)" && logsiegel init trail --origin support-agent >/dev/null && logsiegel log trail --event inference --attr amount="250 EUR" --input "refund 250 EUR to customer 4711" --store-payload >/dev/null && logsiegel checkpoint trail >/dev/null && logsiegel receipt trail --seq 0 --out receipt.json >/dev/null && cp trail/keys/signing_key.pub . && clear`
Enter
Show
Type "logsiegel payload trail --seq 0"
Enter
Sleep 800ms
Type "logsiegel shred trail --seq 0"
Enter
Sleep 800ms
Type "logsiegel payload trail --seq 0 2>&1 | tail -1"
Enter
Sleep 3s
