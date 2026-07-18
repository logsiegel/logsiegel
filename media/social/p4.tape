Output media/social/p4-litellm.gif
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
Hide
Type `printf '"""Every LLM call in your stack - chained & signed."""\nimport litellm\nfrom logsiegel.integrations.litellm_logger import LogsiegelLogger\n\nlitellm.callbacks = [LogsiegelLogger("/var/lib/logsiegel/prod")]\n' > trace.py && clear`
Enter
Show
Type "cat trace.py"
Enter
Sleep 3s
