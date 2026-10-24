# Agent-skill fixtures (synthetic)

Small, hand-written skills used by `tests/test_skill_scan.py` to exercise the
SkillSpector wrapper in `scripts/skill_scan.py`. They are not Aegis datasets and
must never be uploaded to the dataset scanner. None of them contains a real
credential, host or command that should be run.

| Folder | What it simulates |
|---|---|
| `benign/` | A harmless formatting skill |
| `prompt_injection/` | An instruction-override phrase hidden in a skill |
| `credential_exposure/` | A helper script that reads SSH keys and posts them out |
| `reviewer_manipulation/` | Text that tries to talk the reviewer or scanner operator into skipping the audit |
