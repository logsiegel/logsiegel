# B-Roll 1 — „Ein Handlungsprotokoll entsteht" (Verwaltungs-Szenario).
# Render: vhs verifier/broll/01_log_entsteht.tape   (aus dem Repo-Root)

Output verifier/dist/broll/01_log_entsteht.mp4

Set FontSize 26
Set Width 1600
Set Height 900
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 40

Hide
Type "export PATH=/Users/portalix/Projects/logsiegel/.venv/bin:$PATH && cd /tmp && rm -rf broll && mkdir broll && cd broll && clear"
Enter
Show

Type "logsiegel init akte --origin stadt.example/buergerservice-assistent"
Enter
Sleep 2.5s

Type `logsiegel log akte --event system_start --attr model=demo-1`
Enter
Sleep 2s

Type `logsiegel log akte --event inference --attr vorgang=BSV-2026-0142 --pii --store-payload --input "Wohngeld-Antrag Frau Müller, IBAN DE02 1203 0000 0000 2020 51"`
Enter
Sleep 3.5s

Type `logsiegel log akte --event human_override --attr grund=Sachbearbeiterin-korrigiert-Entwurf`
Enter
Sleep 2.5s

Type "logsiegel checkpoint akte"
Enter
Sleep 3s

Type "logsiegel receipt akte --seq 1 --out receipt.json"
Enter
Sleep 3.5s
