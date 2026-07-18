Output media/social/p7-pip.gif
Set Theme "Catppuccin Mocha"
Set FontSize 22
Set Width 1200
Set Height 560
Set Padding 24
Set TypingSpeed 12ms
Hide
Type `export PATH="$PWD/.venv/bin:$PATH" && cd "$(mktemp -d)" && logsiegel init trail --origin support-agent >/dev/null && logsiegel log trail --event inference --attr amount="250 EUR" --input "refund 250 EUR to customer 4711" --store-payload >/dev/null && logsiegel checkpoint trail >/dev/null && logsiegel receipt trail --seq 0 --out receipt.json >/dev/null && cp trail/keys/signing_key.pub . && clear`
Enter
Show
Hide
Type `python3 -m venv fresh && source fresh/bin/activate && clear`
Enter
Show
Type "pip install logsiegel"
Enter
Sleep 6s
Type `python -c "import logsiegel; print(logsiegel._early_access_notice())"`
Enter
Sleep 3s
