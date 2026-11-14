# Проверка версии 0.1.0

Дата: 14 ноября 2026 года. Профиль: local-lab, Python 3.12.14, Linux, один процесс и SQLite. Проверка не является приёмкой RFP.

| Проверка | Результат |
|---|---|
| `python -m unittest discover -s tests -v` | 43 теста пройдены |
| 10 000 tenant-scoped отрицательных чтений | Чужие объекты не раскрыты; это детерминированная выборка, не property-based suite RFP |
| 12 конкурентных одинаковых batch | 1 accepted, 11 duplicates |
| Сквозной HTTP demo | 12 accepted, 12 duplicates, 4 alerts, 1 case, 1 evidence, 2 approvals |
| Независимый verifier demo bundle | valid=true, 1 evidence, 31 audit records, anchored=false |
| SQLite backup | Snapshot создан; restore/evidence equality проверена отдельным тестом |
| Python compileall | Пройдено |
| JavaScript syntax (`node --check`) | Пройдено |
| Chromium UI smoke | Пройден в GitHub Actions: 8 разделов, создание, XSS escaping, 390 px, logout |
| OIDC/MFA, подписанные агенты, mTLS | Не реализовано |
| R1/R2 нагрузка, HA/DR, независимый аудит | Не выполнялось |

Проверка повторного открытия БД не эквивалентна power-loss испытанию. Проверка unique effects не означает end-to-end exactly-once. Локальные тесты согласования не проверяют MFA или подпись agent receipts.

## Открытые ограничения

Нет production identity, tenant RLS, PKI/KMS, системных агентов, шины и аналитического хранилища. Нет полноценной схемы OCSF, временной корреляции, квот, retention, distributed workers, подписанного evidence и исполняемого response. Базовый браузерный сценарий пройден; полный accessibility audit и пользовательская приёмка остаются открытыми.

В `coverage.json` сохраняется каждый из 619 идентификаторов. Частичная локальная реализация не переводится в accepted. Формальные AT: 0 из 192; OMEGA E2E: 0 из 16. Полное ТЗ остаётся открытым.

## CI после исправлений

[Прогон 43563339808](https://github.com/Onmaynec/Bastion-Grid/actions/runs/43563339808) проверяет исходники `8fc738a`. Исправлены явное закрытие SQLite connection и UTF-8 на Windows. Браузерный runner закреплён на Ubuntu 24.04 для Playwright 1.58.0.
