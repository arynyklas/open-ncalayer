# Фикстуры наблюдателя за оригиналом

Синтетические файлы для тестов `cargo xtask upstream` (`xtask/tests/upstream_*.rs`). Всё здесь написано и собрано нами; ни одного файла оригинального NCALayer и ни одной его части здесь нет. Как и другие синтетические фикстуры, файлы распространяются под лицензией репозитория (Apache-2.0).

| Файл | Содержимое |
|---|---|
| `manifest.json` | синтетический манифест по форме `ncalayer.der`: обёртка `{"ncalayer": {…}}`, `syspkgs` строкой через запятую, 5 `disturls` (3 пустые), 4 бандла (2 с `required: true`, один с URL на частный адрес) |
| `manifest.der` | `manifest.json`, подписанный CMS (ГОСТ 34.10-2015-512) синтетическим подписантом `CN=NCALayer, O=OpenNCALayer synthetic, C=KZ`, выпущенным `../synthetic/root-gost2015` |

## Пересоздание

```sh
LANG=C.UTF-8 bash fixtures/upstream/make.sh
```

Подпись ГОСТ рандомизирована, поэтому `manifest.der` не воспроизводится байт в байт; тест `committed_manifest_matches_json` сверяет его содержимое с `manifest.json`.
