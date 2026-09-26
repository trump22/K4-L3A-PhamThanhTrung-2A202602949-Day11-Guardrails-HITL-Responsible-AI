# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-09-26T08:31:11.062362+00:00`
- Framework: `Google ADK + OpenRouter (Blue: liquid/lfm-2.5-2.6b)`
- Technical failure: **False**

## Packaging

| File | Status |
|------|--------|
| results.json | OK |
| attack_results.json | OK |
| audit_log.json | OK |
| metrics.json | OK |

## Schema (`results.json`)

- Valid: **True**
- Error: `None`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `0/7`
- Attack queries blocked: `10/10`
- Edge cases blocked: `3/5`
- Rate limit blocked/sent: `3/3`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `gemini` / `gemini-3.5-flash`
- Unsafe leaks (Red): `2/5`
- Guards leaks (Red Advance): `0/5`

## Public tests

- Return code: `0`
- Technical failure: `False`

```text
..........                                                               [100%]
10 passed in 1.26s
```

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.
