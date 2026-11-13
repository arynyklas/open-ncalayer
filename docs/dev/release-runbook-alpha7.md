# Runbook выпуска 0.1.0-alpha.7 (для мейнтейнера)

Пошаговая инструкция для владельца проекта. Всё публичное делает **владелец**: слияние в `main`, подписанные теги `v0.1.0-alpha.7` и `plugins-ГГГГММДД`, публикация черновика релиза, подпись индексов обновлений его ключом, статус `vm-smoke`. Ассистент готовит всё до подписи и сам ничего не публикует. Документ дополняет [`release.md`](release.md) (оно описывает устройство выпуска, здесь — порядок действий именно для alpha.7) и не заменяет его: если расходится с `release.md`, прав `release.md`, а расхождение надо исправить.

**Статус: alpha.7 выпущена (2026-11-13).** Разделы 1–11 остаются порядком выпуска для следующих версий; что фактически произошло и что осталось открытым — в [`release-alpha7-status.md`](release-alpha7-status.md), поправки к порядку по итогам выпуска — в разделе 12.

Условные обозначения: `<…>` — подставить; команды `cargo`, `git`, `gh` даны для Git Bash в корне рабочего дерева; PowerShell отмечен явно. Пометка **[не проверено]** означает, что команду нельзя безопасно выполнить без публичного действия или без вашего ключа; причина указана рядом.

Решения владельца, на которых построен порядок (не пересматриваются в этом документе):

1. alpha.7 была заблокирована до тех пор, пока не пройдены ручные проверки и матрица ВМ; выпущена с открытыми пунктами, итог по каждому — в [`release-alpha7-status.md`](release-alpha7-status.md).
2. Ядро и плагины выходят вместе: у девяти плагинов `min_core = "0.1.0-alpha.7"`.
3. Шифрование/расшифрование (G01/G02) в alpha.7 **не входит**, документировано как BLOCKED.
4. Гарантия размера документа — **1 ГиБ** (контракт); статус доказательства ведётся в ledger, а не здесь.
5. Секретный ключ подписи индексов никогда не попадает ни в CI, ни к ассистенту.

## 0. Что и где лежит (проверено по файлам)

| Что | Значение | Источник |
|---|---|---|
| Версия рабочего дерева | `0.1.0-alpha.7` | `Cargo.toml`, `[workspace.package]` |
| Тег ядра | `v0.1.0-alpha.7` (до выпуска последним был `v0.1.0-alpha.6`) | `git tag`, `release.md` |
| Открытый ключ обновлений в дереве | `crates/oncl-update/keys/current.pub` (идентификатор minisign `465A2F38D51A8BB6`); `next.pub` нет | файл |
| Каталог `updates/` | До выпуска его не было ни в дереве, ни на `origin/main`: alpha.7 дала первый `beta.json` (PR #8, затем плагины в PR #9) | `index-check.yml`: без `updates/v1` проверяются только ключи |
| Репозиторий | `origin` = `git@github.com:arynyklas/OpenNCALayer.git`; на `origin/main` лежит коммит `70424e67` «Rename repository to OpenNCALayer» | `.git/config`, `git log origin/main` |
| Адрес в текстах этой ветки | `arynyklas/OpenNCALayer` (`release.md`, `scripts/winget/*.ps1`, `xtask winget`, README, документация SDK) | файлы |

Адрес `arynyklas/OpenNCALayer` одинаков в `release.md`, сборке, скриптах WinGet (`-Repository` по умолчанию), `xtask winget` (константа `REPOSITORY`) и ссылках README; в командах ниже `<репозиторий>` = `arynyklas/OpenNCALayer`. Проверка URL в `xtask winget` и в `index check` сравнивает адреса буквально, старое имя `open-ncalayer` она не принимает. **Остаётся вам, на стороне GitHub:** проверить, что старое имя репозитория продолжает перенаправляться (для ссылок из уже выпущенных сборок и закладок) и что новое имя в нужном регистре открывается; это в репозитории не проверяется.

## 1. Предусловия: что должно быть зелёным

Выпуск не начинается, пока каждая строка не закрыта. Итог по этим строкам для alpha.7 — в [`release-alpha7-status.md`](release-alpha7-status.md).

| # | Предусловие | Как проверить | Кто |
|---|---|---|---|
| 1 | Ворота на одном неизменном коммите: `cargo test --workspace --no-fail-fast`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo fmt --all --check`, `cargo deny check`, `cargo xtask privacy`, `cargo xtask licenses --check`, `cargo xtask plugin-ops-check --require-wasm`, `cargo xtask plugin-version-check`, `cargo xtask check-release-features`, `cargo xtask sdk closure` | Выполнить на финальном коммите, без параллельных сборок; сверить с `progress.md` (ledger). Набор команд — раздел «Перед отправкой изменений» README и шаги job `test` в `.github/workflows/ci.yml` | ассистент |
| 2 | Доказательство 1 ГиБ (`cargo xtask platform-proof`, параметры — [`platform-acceptance.md`](platform-acceptance.md)) | Итоговый прогон на финальном дереве (по ledger — переделанный `overload-profile` и полный прогон `--jobs 1`); пока не пройден, поставка с контрактом 1 ГиБ не подтверждена | ассистент; вы принимаете результат |
| 3 | Матрица взаимодействия с NCANode ([`platform-interop.md`](platform-interop.md), [`interop-ncanode.md`](interop-ncanode.md)) | По ledger: 221 PASS, 12 BLOCKED (нет внешней проверки ГОСТ). Прогнать повторно после последних изменений движка (CAdES, приём загрузки) | ассистент |
| 4 | Ветка отправлена и **CI зелёный на всех ногах**, включая macOS и Linux | раздел 2 ниже | вы / ассистент |
| 5 | Матрица ВМ и Win7 пройдены | [`vm-matrix-runbook.md`](vm-matrix-runbook.md) | вы / ассистент при доступе к ВМ |
| 6 | Ручные проверки: одна настоящая подпись через окно плагинов, фокус при 200 %, список непройденных пунктов smoke | [`manual-checks-runbook.md`](manual-checks-runbook.md) | вы |
| 7 | Казахские тексты прочитаны носителем и правки внесены (или принято решение выпускать с пометкой «не вычитано») | [`kk-review-instructions.md`](kk-review-instructions.md) | вы выбираете носителя |
| 8 | Подпись коммитов: `git log --format='%G? %ae' origin/main..HEAD` — у всех `G` и `aryn@sek.su`; 4 коммита `m01@example.invalid` переписаны | раздел 2 | ассистент |
| 9 | Ключ обновлений: секретный ключ в вашем хранилище соответствует `crates/oncl-update/keys/current.pub` | раздел 3 | вы |

## 2. Подготовка ветки и CI (до любых тегов)

Это делает ассистент, вы принимаете результат.

1. Переписать коммиты с чужим автором на `aryn@sek.su` (проверка: `git log --format='%h %ae|%ce %G?' origin/main..HEAD`), перебазировать ветку на `origin/main` и заново прогнать ворота из строки 1 таблицы.
2. Отправить ветку **без PR**, чтобы запустить CI: `git push origin feat/platform-sdk-apps` [не проверено: публичное действие]. На обычный пуш ветки запускаются `ci.yml` и `privacy.yml`; `index-check.yml`, `release.yml`, `plugins.yml` не запускаются (триггеры — раздел 7 ниже). Последующие пуши — обычные (без `--force`).
3. Дождаться зелёного `ci.yml` на всех ногах: `test` (ubuntu-24.04, windows-2025, macos-15), `win7` (x64, x86), `windows-package`, `macos-universal`, `linux-appimage`, `builtins-x86`, `ext-e2e`, `tokens-vpcd`, `actionlint`, `fmt`, `clippy`, `deny`, `site`, `extension`. Ноги `live` и `bench` на пуш не запускаются (по расписанию или вручную). Любой красный результат — стоп: исправление и снова ворота.
4. Проверить, что privacy дошла до конца: `privacy.yml` без секрета `PRIVACY_DENYLIST` пишет notice и проходит; структура проверяется всегда. Ваш приватный список проверяет хук `pre-push` вашего checkout (`release.md`, §9).

## 3. Подготовка ключа обновлений (один раз, у вас)

Секретный ключ хранится офлайн, пароль вводится без эха (`release.md`, §1).

1. Если пары ещё нет: `cargo xtask sign keygen --out <каталог вне репозитория>`. Если пара есть, пропустить.
2. Убедиться, что открытая часть вашей пары совпадает с встроенной в дерево:

   ```sh
   diff <каталог>/oncl-index.pub crates/oncl-update/keys/current.pub && echo совпадает
   ```

   Расхождение — стоп: сборка alpha.7 встроит не ваш ключ, а `index check` отвергнет подпись (проверяется только `current.pub`). Исправить `current.pub` нужно **до** тега и до слияния в `main`, потому что job `index` и `index check` читают ключ из тега.
3. Копия без ключа не умеет обновляться; alpha.6 собрана без ключа, поэтому её установки сами на alpha.7 не перейдут — переустановка вручную (`release.md`, §1).

## 4. Слияние в `main` (вы)

Условие: раздел 2 закрыт, предусловия 1–9 закрыты.

- Через PR на GitHub (предпочтительно: правило «Index check» увидит изменение) или быстрой перемоткой: `git switch main && git merge --ff-only feat/platform-sdk-apps && git push origin main`. Прямой пуш в `main` проходит только если вы в списке обхода правила (`release.md`, §2) **[не проверено: зависит от настроек репозитория]**. Слияние должно сохранить подписанные коммиты; слияние кнопкой GitHub подписывает свой коммит ключом GitHub — это допустимо, тег подписываете вы.
- Перед слиянием `main` должен совпадать с базой, на которую перебазирована ветка (`git fetch origin && git log --oneline origin/main..HEAD`).

## 5. Разовые настройки репозитория (вы, до первого тега)

Их меняет только владелец (`release.md`, §2). Проверка: каждый пункт видно в Settings.

| Настройка | Где | Зачем |
|---|---|---|
| Pages → Source: **GitHub Actions** | Settings → Pages | без этого `pages.yml` не публикует индекс (в журнале `::notice::Pages is not enabled`) |
| **Allow GitHub Actions to create and approve pull requests** | Settings → Actions → General | иначе job `index` не откроет PR с индексом |
| Обязательная проверка **Index check / check** для `main` | Settings → Rules (или Branches) | без неё PR с неподписанным индексом можно слить; она всегда отчитывается, обычные PR не держит |
| Список обхода правила для вас (только если нужен прямой пуш) | то же правило | `release.md`, §2 |

Состояние этих настроек на репозитории **не проверялось**: нет доступа к настройкам.

## 6. Выпуск ядра `v0.1.0-alpha.7`

### 6.1 Тег (вы)

На коммите в `main`, где `Cargo.toml` = `0.1.0-alpha.7`:

```sh
git tag -s v0.1.0-alpha.7 -m "OpenNCALayer 0.1.0-alpha.7"
git tag -v v0.1.0-alpha.7
git push origin v0.1.0-alpha.7
```

Что смотреть в выводе `git tag -v`: строка `Good "git" signature` (для SSH-подписи) или `Good signature from …` (для GPG), ваш отпечаток ключа, имя тега и сообщение. Нет подписи или она не сходится — **тег не отправляется**: `git tag -d v0.1.0-alpha.7` и заново. Ключ — `user.signingkey` в вашей конфигурации; убедитесь, что для этого checkout применяется личность `aryn@sek.su` (`git config user.email`, `git config user.signingkey`), иначе тег подпишется другим ключом. Команды выпуска — из `release.md`, §3 шаг 2 (проверено по тексту).

### 6.2 Что сделает CI

Пуш тега `v*` запускает `release.yml`. Первым job `version` сверяет тег с `Cargo.toml`; суффикс `-alpha.7` — pre-release, идёт только в канал `beta`. Дальше: `builtins`, `binaries` (шесть флейворов: `win-x64`, `win-x86`, `win7-x64`, `win7-x86`, `linux-x64`, `osx`), `extension`, `sbom`, `conformance` (артефакт, не публикуется), `platform`, `platform-sbom`, `publish`, `index`. `publish` создаёт **черновик** (`gh release create … --prerelease --draft`, `release.yml`). Подпись кода (SignPath, Apple) выполняется только если заданы секреты, иначе пропускается с notice.

Ожидаемый результат: черновик релиза `OpenNCALayer 0.1.0-alpha.7` с установщиками `openncalayer-0.1.0-alpha.7-<флейвор>-setup.exe`, `…-win-x64-winget-setup.exe`, `…-win-x86-winget-setup.exe`, `.pkg`, `.zip`, `.AppImage`, `SHA256SUMS`, `builtins-SHA256SUMS`, пакеты `oncl-*` и `oncl-server-*`; job `index` открывает PR `updates/v0.1.0-alpha.7` с неподписанным `updates/v1/beta.json` (для pre-release — только `beta`). Если в теге нет доверенного ключа обновлений, job `index` PR не откроет и напишет notice — тогда ключ из раздела 3 не попал в тег; тег удаляется (раздел 9) и выпуск повторяется после исправления.

### 6.3 Проверка черновика (вы)

1. Сверка встроенных модулей: ассет `builtins-SHA256SUMS` кладётся в пустой каталог как `SHA256SUMS`, распаковывается программа флейвора (хотя бы один Windows и `linux-x64`), затем `cargo xtask builtins check --bin <программа> --dir <каталог>`. Должно быть: вшиты все четыре модуля в том виде, как собрал job `builtins`. Расхождение — черновик не публикуется (`release.md`, §3 шаг 3).
2. Происхождение файлов: `gh attestation verify <файл> --repo <репозиторий>` (`release.md`, §8). Для черновика команда может не найти опубликованного — **[не проверено на черновике]**.
3. VM-матрица и Win7 на установщиках этого прогона — [`vm-matrix-runbook.md`](vm-matrix-runbook.md). Для alpha.7 есть расхождение между документами и скриптами (скрипты WinGet требуют stable-тег): оно описано там и в списке блокеров.

### 6.4 Статус `vm-smoke` (вы)

Когда матрица и Win7 пройдены, статус ставите вы на коммит тега (раньше его ставил агент лаборатории; `release.md`, §3 шаг 3 и `update-index.md`). `index check` читает «комбинированный статус» коммита тега (`GET /repos/<репозиторий>/commits/<тег>/status`, `xtask/src/index.rs`) и ищет контекст ровно `vm-smoke` со статусом `success`. Поставить:

```sh
sha=$(git rev-parse "v0.1.0-alpha.7^{commit}")
gh api "repos/<репозиторий>/statuses/$sha" -f state=success -f context=vm-smoke \
  -f description="matrix and Win7 passed, see lab record"
```

**[не проверено]**: вызов `POST /repos/{owner}/{repo}/statuses/{sha}` — публичное действие, на репозитории не выполнялся; нужен токен с правом записи статусов. Красный итог матрицы — ставится `state=failure`, черновик не публикуется. Статус `conformance` для pre-release в `beta` **не нужен** (`release.md`, §3 шаг 3, §4 шаг 3).

### 6.5 Публикация черновика (вы)

```sh
gh release edit v0.1.0-alpha.7 --draft=false
```

(форма `--draft=false` — из справки `gh release edit` и `release.md`.) PR индекса для черновика проходит `index check` только после публикации: ссылки на ассеты черновика не открываются (`HEAD` ≠ 200). Опубликованный pre-release не получает флаг Latest у ядра.

### 6.6 Подпись и слияние индекса (вы)

На ветке PR `updates/v0.1.0-alpha.7` (`release.md`, §4):

```sh
git fetch origin
git switch updates/v0.1.0-alpha.7
cargo xtask sign updates/v1/beta.json --key <каталог>/oncl-index.key
cargo xtask index check updates/v1 --base origin/main --vm-smoke --conformance
```

- Пароль вводится без эха. Файл индекса руками не форматируется (публикуется байт в байт); допустима только правка значения `rollout` до подписи.
- Для pre-release подписывается один файл: `beta.json`. `stable.json` для alpha.7 не создаётся.
- `--conformance` в проверке PR (`index-check.yml`) запускается всегда, но для версии, идущей только в `beta`, статус не требуется (`update-index.md`). Локально можно опустить `--conformance`.
- Ожидаемый вывод `index check` без ошибок — завершение с кодом 0; ошибки печатаются с причиной (подпись не тем ключом, `seq` не вырос, `HEAD` ≠ 200, нет статуса `vm-smoke`).
- Закоммитить `updates/v1/beta.json` вместе с `updates/v1/beta.json.minisig`, запушить. Проверка `index-check.yml` стартует именно на этот пуш. Слить PR после зелёной проверки. Далее `pages.yml` публикует `updates/` на Pages: `https://arynyklas.github.io/OpenNCALayer/updates/v1/beta.json`.
- После слияния: `curl -fsS https://arynyklas.github.io/OpenNCALayer/updates/v1/beta.json.minisig` должен вернуть подпись (`release.md`, §8).

Если до слияния вышла ещё одна версия, у второго PR конфликт по `seq`: конфликт **не разрешать вручную**, перезапустить job `index` (Actions → Release → Re-run job `index`) после слияния первого и подписать заново (`release.md`, §4).

### 6.7 Порядок «ядро, затем плагины»

Плагины alpha.7 выпускаются **после** того, как PR индекса ядра слит и опубликован. Причины:

1. `min_core = "0.1.0-alpha.7"` у девяти плагинов (`rating1c`, `dogovor24`, `efactoring`, `market`, `energy`, `eproc`, `esf-osdkz`, `fhs`, `qiwi`) означает: «самая старая версия ядра, на которой плагин работает; более старое ядро эту версию не ставит» (`update-index.md`, `crates/oncl-update/src/plugins.rs`: выбирается версия при `min_core <= ядро`). Клиент alpha.6 просто не увидит эти версии: вреда нет, но и пользы тоже — окно ручных операций есть только в alpha.7.
2. Оба PR правят `updates/v1/beta.json` и поднимают один и тот же следующий `seq`; второй PR конфликтует с первым. Если плагины тегируются после слияния PR ядра, job плагинов собирает индекс от свежего `main`.
3. `cargo xtask plugin pending --channel beta` сверяется с индексом в рабочем дереве: он показывает правду, только если на `main` уже лежит опубликованный `beta.json`. Пока индекса нет, `pending` печатает все порты (`xtask/src/plugin.rs`); см. раздел 7, шаг 1.

## 7. Выпуск плагинов `plugins-ГГГГММДД`

Предусловие: раздел 6 завершён (индекс ядра опубликован).

1. Какие порты выйдут — на `main`, у вас:

   ```sh
   git switch main && git pull --ff-only
   cargo xtask plugin pending --channel beta
   ```

   **Находка (по `git ls-tree origin/main` до выпуска):** пока в индексе нет плагинов, `cargo xtask plugin pending` считает ожидающими **все** порты (`xtask/src/plugin.rs`, `pending`: без записей `published` пуст); портов с `plugin.toml` в дереве 34, и `plugins.yml` соберёт и опубликует их все. Для alpha.7 владелец выбрал выпуск всех 34 одним тегом (изменились девять: `dogovor24`, `efactoring`, `energy`, `eproc`, `esf-osdkz`, `fhs`, `market`, `qiwi`, `rating1c`). Альтернатива — сначала внести в индекс пакеты прошлых релизов командой `cargo xtask index add-plugin --channel beta --tag <тег> --package <файл.onclp>…`, но она требует релиза с пакетами на GitHub: у тега `plugins-20261031` релиза нет (есть только `plugins-20261031.1` и `plugins-20261101`). `cargo xtask plugin-version-check` сравнивает рабочее дерево с последним тегом `plugins-*` и сообщает порт, у которого изменился код, а версия нет.
2. Тег на `main`:

   ```sh
   git tag plugins-ГГГГММДД
   git push origin plugins-ГГГГММДД
   ```

   Команда из `release.md`, §7а (без `-s`; `release.md` для плагинов требует простой тег). Вы решили подписывать и теги `plugins-*`: тогда `git tag -s plugins-ГГГГММДД -m "OpenNCALayer plugins ГГГГММДД"` и `git tag -v plugins-ГГГГММДД`; `plugins.yml` подпись не проверяет (проверяется только имя `^plugins-[0-9]{8}(\.[0-9]+)?$`). Второй тег за день — `plugins-ГГГГММДД.1`.
3. `plugins.yml`: собирает каждый порт из `pending` дважды (`cargo xtask plugin pack`) и сравнивает пакеты байт в байт, проверяет `cargo xtask licenses --plugins --check`, публикует pre-release без Latest с `THIRD-PARTY.txt`, `SHA256SUMS`, аттестацией; затем открывает PR `updates/<тег>` с неподписанным `beta.json` (`cargo xtask index add-plugin --channel beta`). Если выпускать нечего — workflow завершается notice без релиза.
4. На ветке PR у вас (`release.md`, §7а):

   ```sh
   git fetch origin && git switch updates/plugins-ГГГГММДД
   cargo xtask sign updates/v1/beta.json --key <каталог>/oncl-index.key
   cargo xtask index check updates/v1 --base origin/main
   ```

   Закоммитить индекс с `.minisig`, запушить, дождаться зелёного `index-check.yml`, слить. Флаг `--vm-smoke` здесь не нужен: в PR плагинов нет новых версий ядра, гейты `vm-smoke` и `conformance` относятся только к ядру (`update-index.md`).
5. В `stable` плагины в alpha.7 **не** идут: версии `1.0.0-beta.N` — предварительные, `index add-plugin --channel stable` их не добавит, а `registry.toml` портов — `conformance = "computed"`.

Проверка собственного результата: `curl -fsS https://arynyklas.github.io/OpenNCALayer/updates/v1/beta.json | …` по `id`/`version` плагинов; клиент подхватывает плагины при следующей проверке индекса.

## 8. Секреты и переменные по workflow (только имена)

Секретов, обязательных для выпуска, **нет**: без них шаги подписи пропускаются с уведомлением. Токен `github.token` (встроенный) используют `release.yml`, `plugins.yml`, `index-check.yml`, `aur.yml`, `pages.yml` — настраивать не нужно.

| Workflow | Имя | Вид | Обязательно? | Если нет |
|---|---|---|---|---|
| `release.yml` | `SIGNPATH_API_TOKEN` | секрет | нет | подпись Authenticode пропущена, релиз неподписан |
| `release.yml` | `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`, `SIGNPATH_SIGNING_POLICY_SLUG` | переменные | нет (нужны вместе с токеном) | то же |
| `release.yml` | `APPLE_CERTIFICATE_P12`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGN_IDENTITY`, `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD` | секреты | нет (все вместе) | `.app` не подписано и не нотаризовано |
| `release.yml` | `APPLE_INSTALL_IDENTITY` | секрет | нет | `.pkg` не подписан |
| `ci.yml` (job `extension`) | `AMO_JWT_ISSUER`, `AMO_JWT_SECRET` | секреты | нет; используются только на тегах `v*` | подпись расширения Firefox пропущена |
| `privacy.yml` | `PRIVACY_DENYLIST` | секрет (base64 файла) | нет | шаг denylist пишет notice и проходит |
| `aur.yml` | `AUR_PUBLISH` | переменная (`true`) | нет | AUR только собирается и проверяется |
| `aur.yml` | `AUR_SSH_PRIVATE_KEY` | секрет | нужен только при `AUR_PUBLISH=true` | при `AUR_PUBLISH=true` без ключа workflow падает |
| `upstream.yml` | `UPSTREAM_SOURCE` | переменная | нет | при значении `lab` расписание не запускает наблюдателя |
| `winget.yml`, `pages.yml`, `plugins.yml`, `index-check.yml` | — | — | — | только `github.token` |

Для alpha.7 `winget.yml` не сработает: он пропускает не-stable теги (`winget.md`). `aur.yml` следует за Release, но публикует только при `AUR_PUBLISH`.

Источники: `grep 'secrets\.\|vars\.' .github/workflows/*.yml` и `release.md`, §2 (проверено).

Ключ подписи индексов (`oncl-index.key`) в этой таблице **отсутствует намеренно**: он не секрет GitHub и не передаётся в CI.

## 9. Откат: что делать, если шаг упал

| Ситуация | Действие |
|---|---|
| Тег поставлен локально, не отправлен | `git tag -d v0.1.0-alpha.7`, исправить, поставить заново |
| Тег отправлен, `release.yml` упал до `publish` | Исправить причину; тег удалить на удалённом репозитории и поставить заново на исправленном коммите: `git push origin :refs/tags/v0.1.0-alpha.7` (или `git push origin --delete v0.1.0-alpha.7`), `git tag -d v0.1.0-alpha.7`, снова раздел 6.1 [не проверено: публичное действие]. Перенос подписанного тега считается новым выпуском: проверка `index` читает ключ из тега, а у клиентов тег ещё не использовался |
| Черновик создан, но сборка плохая | Удалить черновик вместе с тегом: `gh release delete v0.1.0-alpha.7 --cleanup-tag --yes` (флаги `--cleanup-tag`, `--yes` — по справке `gh release delete`) [не проверено на репозитории]. Закрыть PR `updates/v0.1.0-alpha.7`, удалить ветку `updates/v0.1.0-alpha.7` |
| Матрица ВМ красная | `vm-smoke` не ставится или ставится `failure`; черновик не публикуется (`release.md`, §3 шаг 3). Исправления — новая версия (`alpha.8`): опубликованный и затем отозванный pre-release не «переиспользуется» |
| Черновик опубликован, индекс не слит | Установки не затронуты: клиенты видят версию только через индекс. Можно удалить релиз (`gh release delete`) или выпустить новую версию |
| PR индекса слит, версия плохая | Отзыв: `"revoked": true` у записи в `updates/v1/beta.json`, затем `cargo xtask index refresh --channel beta`, `cargo xtask sign updates/v1/beta.json --key <каталог>/oncl-index.key`, `cargo xtask index check updates/v1 --base origin/main`, PR и слияние (`release.md`, §6; для pre-release — только `beta`) |
| Подпись индекса не тем ключом | `index check` отвергнет; `current.pub` дерева ≠ вашей пары: раздел 3. Менять ключ в теге нельзя — нужна новая версия |
| `index check`: «has no successful vm-smoke status» | статус не поставлен или поставлен не на тот коммит: `git rev-parse v0.1.0-alpha.7^{commit}` должен совпасть со `sha` статуса; после постановки Actions → Index check → Re-run |
| `index` job не открыл PR | Проверить: Settings → Actions → «Allow GitHub Actions to create and approve pull requests»; ключ в теге (раздел 6.2) |
| Плагины: пакеты не совпали при двойной сборке | Релиз не создаётся; исправить порт; новый тег `plugins-ГГГГММДД.1` |
| Тег `plugins-*` с ошибкой | Удалить релиз, `gh release delete plugins-ГГГГММДД --cleanup-tag --yes`, закрыть PR `updates/plugins-ГГГГММДД` [не проверено] |

## 10. После выпуска

- `gh attestation verify <файл> --repo <репозиторий>` для файлов релиза.
- Индекс опубликован (команда `curl` в разделе 6.6).
- Продление индекса: каждый индекс, не менявшийся 30 дней, надо продлить и подписать заново (`cargo xtask index refresh --channel beta`, подпись, PR); `stable.json` для alpha.7 не создаётся (`release.md`, §5).
- Обновить [`release-alpha7-status.md`](release-alpha7-status.md) (или итоговый документ следующего выпуска): закрытые строки — «закрыто» с датой.

## 11. Чего в этом документе нет

- Публикации в WinGet (stable-релиз и отдельная команда владельца; `winget.md`).
- Шифрования и расшифрования (G01/G02): BLOCKED.
- Автоматизации матрицы ВМ: описана в [`vm-matrix-runbook.md`](vm-matrix-runbook.md), раздел «Что автоматизирует ассистент».

## 12. Как прошёл выпуск alpha.7: поправки к порядку

Проверено на выпуске 2026-11-13; всё остальное в разделах 1–11 не опровергнуто, но и не проверялось отдельно.

1. **Слияние в `main`.** Правило ветки требует проверку `check` (`index-check.yml`). Порядок, который сработал: открыть PR `feat/...` → `main` только ради этой проверки и, когда `check` зелёный, отправить тот же коммит в `main` обычным пушем без `--force` (`git push origin <sha>:refs/heads/main`). До завершения `check` правило отвечает «Required status check "check" is in progress» и пуш не принимает. Остальные джобы `ci.yml` на PR слиянию не мешали, но их надо дождаться: PR #10 был слит до их окончания, и это был риск; полный CI на `main` после слияния прошёл зелёным.
2. **Тег.** `git tag -s`, затем `git tag -v` (должно быть `Good "git" signature` и ваш отпечаток) и только потом `git push origin <тег>`. `release.yml` собрал черновик за ~1 ч (44 файла на момент проверки); job `index` сам открыл PR `updates/v0.1.0-alpha.7` с неподписанным индексом.
3. **`xtask index check` локально** читает токен только из переменной окружения `GITHUB_TOKEN`; без неё запрос статуса коммита уходит анонимно и GitHub отвечает `403 Forbidden`. Достаточно задать её на время сессии, например `GITHUB_TOKEN=$(gh auth token)`.
4. **Порядок трёх публичных шагов:** статус `vm-smoke` на коммит тега → публикация черновика (`gh release edit <тег> --draft=false`) → подпись индекса в PR. `index check` проверяет, что ссылки на файлы релиза отвечают 200, а у черновика они не открываются.
5. **Подпись индекса** на ветке PR: `cargo xtask sign updates/v1/beta.json --key <каталог>/oncl-index.key`, затем `cargo xtask index check updates/v1 --base origin/main` (локально для ядра с `--vm-smoke`), коммит `beta.json` и `beta.json.minisig` подписанным коммитом, пуш и слияние PR после зелёного `check`. Страница Pages обновляется через несколько минут после слияния.
6. **Плагины.** Второй тег за день — `plugins-ГГГГММДД.1`. Каждый тег `plugins-*` открывает свой PR индекса. Неслитые PR старых тегов (`plugins-20261031.1`, `plugins-20261101`) закрыты как устаревшие после слияния индекса, перекрывающего их пакеты (сверено по списку пакетов в теле PR); конфликт `seq` в них не проверялся.
7. **Отказ слияния PR индекса.** Если `gh pr merge` отвечает «base branch policy prohibits the merge», проверка `check` ещё не закончилась: повторить после зелёного результата, `--admin` не использовать.
8. **Что осталось неподтверждённым даже после выпуска:** обновление уже установленной копии по индексу (клиент ставит версию из `beta.json`) на ВМ не проверялось.
