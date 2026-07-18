# Logsiegel-Demo-GIF: Receipt → Tamper → FAIL → Receipt beweist offline.
# Rendern:  vhs media/demo.tape   (aus dem Repo-Root; braucht .venv mit -e Install)

Output media/demo.gif

Set Theme "Catppuccin Mocha"
Set FontSize 20
Set Width 1200
Set Height 660
Set Padding 24
Set TypingSpeed 35ms

Hide
Type `export PATH="$PWD/.venv/bin:$PATH" && cd "$(mktemp -d)" && clear`
Enter
Show

Type "logsiegel init trail --origin support-agent"
Enter
Sleep 1.5s

Type `logsiegel log trail --event inference --attr amount="250 EUR" --input "refund 250 EUR to customer 4711" --store-payload`
Enter
Sleep 2.5s

Type "logsiegel checkpoint trail"
Enter
Sleep 1.5s

Type "logsiegel receipt trail --seq 0 --out receipt.json"
Enter
Sleep 1.5s

Type "logsiegel verify trail"
Enter
Sleep 2.5s

Type `# now someone quietly edits the log after the fact ...`
Enter
Type `sed -i '' 's/250 EUR/950 EUR/' trail/log.jsonl`
Enter
Sleep 1.5s

Type "logsiegel verify trail"
Enter
Sleep 3.5s

Type `# the receipt you handed out earlier still proves the truth — offline:`
Enter
Type "logsiegel verify-receipt receipt.json --pubkey trail/keys/signing_key.pub"
Enter
Sleep 5s
