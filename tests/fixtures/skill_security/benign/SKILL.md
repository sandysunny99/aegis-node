---
name: csv-header-tidy
description: Rename CSV header cells to snake_case when the user asks to tidy a header row.
---

# CSV header tidy

When the user pastes a CSV header row, return the same columns renamed to
snake_case. Do not change any data rows. Show the result as a code block and
ask the user to confirm before writing it to a file.
