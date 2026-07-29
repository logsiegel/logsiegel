# B-Roll 2 — „Manipulation fliegt auf": verify PASS → 1 Wert geändert → FAIL.
# Render: vhs verifier/broll/02_manipulation.tape   (aus dem Repo-Root)

Output verifier/dist/broll/02_manipulation.mp4

Set FontSize 26
Set Width 1600
Set Height 900
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 40

Hide
Type "export PATH=/Users/portalix/Projects/logsiegel/.venv/bin:$PATH && cd /tmp && rm -rf broll2 && mkdir broll2 && cd broll2"
Enter
Type "logsiegel init akte --origin stadt.example/buergerservice-assistent >/dev/null"
Enter
Type "logsiegel log akte --event system_start --attr model=demo-1 >/dev/null"
Enter
Type `logsiegel log akte --event inference --attr vorgang=BSV-2026-0142 --pii --store-payload --input "Wohngeld-Antrag Frau Müller, IBAN DE02 1203 0000 0000 2020 51" >/dev/null`
Enter
Type `logsiegel log akte --event human_override --attr grund=Sachbearbeiterin-korrigiert-Entwurf >/dev/null`
Enter
Type "logsiegel checkpoint akte >/dev/null && clear"
Enter
Show

Type "logsiegel verify akte"
Enter
Sleep 3s

Type `sed -i '' 's/BSV-2026-0142/BSV-2026-9999/' akte/log.jsonl`
Enter
Sleep 2s

Type "logsiegel verify akte"
Enter
Sleep 5s
