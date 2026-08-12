# LogSeeker標準タクソノミー v1.8

- 更新日: 2026-08-12
- マスター: `docs/taxonomy.md`
- 実データ参照: 開発・検証環境から取得した最近のWeb、Linux audit、Linux、Windowsイベントのサンプル

## 0. 文書の位置づけ
本書はLogSeeker基本設計の下位に位置する**共通仕様・マスター**であり、LogSeekerが機能対象として扱う受信フィールド名の唯一のマスターである。

- 上位文書: `PROJECT.md`（最新の基本設計）
- 関連文書: `docs/normalize-mapping.md`
- 基本設計と本書が矛盾する場合は、**基本設計を正として本書を修正する。**
- 各詳細設計・実装資料は、本書にないpayload KEYをLogSeekerの受信フィールドとして独自追加・改名・定義してはならない。

## 1. 目的
LogSeekerで機能対象として扱うJSON KEYの一覧と、各KEYの型を定義する。

LogSeekerが受け取るデータは単純な **KEY:VALUE** である。Taxonomyの役割は、受信payloadのKEY名が本書のKEY一覧と完全一致したとき、そのKEYを表示・検索・集計・解析等の機能対象として認識することにある。

本タクソノミーは、KEYを別のKEYへ変換する表ではない。`class` も他のKEYと同じTaxonomy KEYであり、LogSeekerが他のKEYからClassを推測するための表でもない。Taxonomy外KEYは受信してpayloadへ無改変保存するが、それ以外には使用しない。

## 2. 最重要原則
- **LogSeekerは受信したJSON payloadを改変しない。**
- **受信したKEY名を別のKEY名へ読み替えない。** `vhost` を `virtualhost` に変換する、`client` を `srcipv4` に変換する等の受信後変換は行わない。
- **受信フィールドは、本書に定義されたTaxonomy KEYと完全一致するKEYだけとする。**
- Taxonomy KEYと一致した受信フィールドは、各機能仕様に従って表示・検索・集計・Dashboard・Rule・Correlation・Entity・GeoIP等で利用できる。
- Taxonomy外KEYは受信・無改変保存するが、**表示・検索・集計・解析その他の機能には使用しない。** 検索用インデックス、表示候補、Dashboard候補、Rule / Correlation / Entity / GeoIP等の入力へ展開しない。
- Taxonomy外KEYをTaxonomy KEYへ改名、コピー、補完して機能対象にしてはならない。
- 同じ意味に見える複数KEYがpayloadに存在しても、一方へ統合しない。Taxonomy外KEYはpayloadに残るだけである。
- VALUEがないKEYを、別のKEYのVALUEで補完しない。KEY自体が存在しない場合も新規追加しない。
- ログ本文に存在しない値をLogSeekerが推測して追加しない。ログファイル・送信設定から一意に確定できる値は、NXLog等のログ送信元がJSON生成時に明示的に付与してよい。
- `source` / `source_name` はログソース管理メタデータであり、受信JSONのKEYとは別に扱う。
- **`class` はTaxonomy KEYである。** VALUEはログやイベントの種類・ログソースを識別するクラス名として、そのまま扱う。
- ログ送信元は原則としてJSON生成時に `class` を設定する。LogSeekerは `class` のVALUEを別名へ読み替え・推測・補完しない。
- `class` が存在しない場合、LogSeekerは `class=unknown` 等を自動追加しない。
- `source_type` は現行実装上の旧フィールドであり、Taxonomy KEYではない。新規送信JSONでは `class` を使用する。
- `source` / `source_name` / `received_at` 等のLogSeeker管理メタデータ、およびGeoIP等の派生メタデータは受信フィールドとは別体系とし、それぞれの詳細設計に従う。

## 3. 標準タクソノミー 全KEY

以下を **LogSeeker標準Taxonomy KEYの正式マスター** とする。

**この一覧が先に存在し、`class` のVALUEはこのKEY一覧を制限しない。** 受信payloadに同名KEYが存在すれば、そのKEYはTaxonomy受信フィールドとして機能対象になり得る。

例: `accountname` が存在してもクラス名は決まらない。クラス名は受信JSONの `class` VALUEである。`accountname` と `class` は独立したKEY:VALUEとして扱う。

全KEYをDB物理カラム化したり、すべて初期表示したりすることを意味しない。


| KEY | 型 |
|---|---|
| `accesses` | `string` |
| `accessgroup` | `string` |
| `accessmask` | `string` |
| `accountdomain` | `string` |
| `accountid` | `string` |
| `accountname` | `string` |
| `ackduration` | `integer` |
| `acktime` | `string` |
| `acktimeutc` | `string` |
| `aclname` | `string` |
| `aclnumber` | `integer` |
| `acquire_attempt_count` | `number` |
| `acquired_at_time` | `string` |
| `acquired_by` | `string` |
| `action` | `string` |
| `actioncode` | `integer` |
| `activity` | `string` |
| `activityid` | `string` |
| `actor` | `string` |
| `addl` | `string` |
| `ag_count` | `number` |
| `agent` | `string` |
| `agentdomain` | `string` |
| `agenthostname` | `string` |
| `agentid` | `string` |
| `agentip` | `string` |
| `agentloggedonusers` | `string` |
| `agentmac` | `string` |
| `agentos` | `string` |
| `agentstatus` | `string` |
| `agentversion` | `string` |
| `alert_product` | `string` |
| `alert_time` | `string` |
| `alertdomain` | `string` |
| `alerted` | `boolean` |
| `alerturi` | `string` |
| `alerturl` | `string` |
| `alexa_rank` | `number` |
| `ami` | `string` |
| `ami_description` | `string` |
| `ami_name` | `string` |
| `ami_owner` | `string` |
| `ami_platform` | `string` |
| `analyzer` | `string` |
| `answer` | `string` |
| `apipv4` | `ipv4` |
| `apipv6` | `ipv6` |
| `apmac` | `mac` |
| `apname` | `string` |
| `appcategory` | `string` |
| `appdesc` | `string` |
| `appid` | `string` |
| `application` | `string` |
| `apppath` | `string` |
| `appproperties` | `string` |
| `archive_id` | `string` |
| `args` | `string` |
| `asn` | `string` |
| `asset` | `object` |
| `assets` | `array` |
| `attachment` | `string` |
| `attack` | `string` |
| `attackinfo` | `string` |
| `attemptingAcquire` | `boolean` |
| `audititemid` | `string` |
| `auth` | `string` |
| `auth_success` | `boolean` |
| `authmethod` | `string` |
| `authoritativeanswer` | `boolean` |
| `av_hits` | `string` |
| `ax_malicious_alerts` | `string` |
| `ax_score` | `boolean` |
| `bay` | `string` |
| `behavior` | `string` |
| `binary_can_sleep` | `string` |
| `binary_languages` | `string` |
| `binarystate` | `boolean` |
| `bytes` | `integer` |
| `bytespersec` | `number` |
| `cachetype` | `string` |
| `cacheval` | `string` |
| `callid` | `string` |
| `callingdomain` | `string` |
| `callinglogonid` | `string` |
| `callingsrcip` | `string` |
| `callingsrcipv6` | `ipv6` |
| `callinguid` | `string` |
| `callingusername` | `string` |
| `callingusersecurityid` | `string` |
| `capture_password` | `boolean` |
| `category` | `string` |
| `cc` | `string` |
| `cert_chain` | `string` |
| `cert_chain_fuids` | `string` |
| `cert_count` | `number` |
| `cert_errors` | `string` |
| `cert_permanent` | `boolean` |
| `cert_type` | `string` |
| `certname` | `string` |
| `certsubject` | `string` |
| `charencoding` | `string` |
| `cidr` | `string` |
| `cipher` | `string` |
| `city` | `string` |
| `class` | `string` |
| `classid` | `string` |
| `client` | `string` |
| `client_cert_chain` | `string` |
| `client_cert_chain_fuids` | `string` |
| `client_depth` | `number` |
| `client_key_exchange_seen` | `boolean` |
| `client_ticket_empty_session_seen` | `boolean` |
| `client_uuid` | `string` |
| `clientissuersubject` | `string` |
| `clientsubject` | `string` |
| `clientvars` | `string` |
| `closeduration` | `integer` |
| `closetime` | `string` |
| `closetimeutc` | `string` |
| `cmdarg` | `string` |
| `cnchost` | `string` |
| `cncipv4` | `string` |
| `cncport` | `number` |
| `compile_time` | `string` |
| `compression_alg` | `string` |
| `confidence` | `string` |
| `connectionid` | `string` |
| `connections` | `integer` |
| `connstate` | `string` |
| `containduration` | `integer` |
| `containtime` | `string` |
| `containtimeutc` | `string` |
| `content` | `string` |
| `context_tags` | `string` |
| `continent` | `string` |
| `cookievars` | `string` |
| `count` | `number` |
| `count_updated_at_time` | `string` |
| `country` | `string` |
| `countrycode` | `string` |
| `createdtime` | `string` |
| `createdtimeutc` | `string` |
| `creatorprocessid` | `string` |
| `current_status` | `string` |
| `current_status_txt` | `string` |
| `curve` | `string` |
| `customer` | `string` |
| `customercode` | `string` |
| `cveid` | `string` |
| `cwd` | `string` |
| `data_channel` | `string` |
| `day` | `string` |
| `dbinstance` | `string` |
| `dbname` | `string` |
| `dbtable` | `string` |
| `dcid` | `integer` |
| `defgw` | `string` |
| `depth` | `string` |
| `description` | `string` |
| `desktop_height` | `number` |
| `desktop_width` | `number` |
| `detect_ruleids` | `array` |
| `detect_rulematch` | `object` |
| `detect_rulematches` | `array` |
| `detect_rulenames` | `array` |
| `detectedtime` | `string` |
| `detectedtimeutc` | `string` |
| `deviceid` | `string` |
| `devicename` | `string` |
| `devicetype` | `string` |
| `dhcpscope` | `string` |
| `direction` | `string` |
| `disabled_aids` | `number` |
| `disk` | `string` |
| `disposition` | `string` |
| `distance` | `number` |
| `dns_lookups` | `string` |
| `domain` | `string` |
| `domain_category` | `string` |
| `done` | `boolean` |
| `driver` | `string` |
| `dropped` | `boolean` |
| `dstareacode` | `string` |
| `dstasn` | `string` |
| `dstasorg` | `string` |
| `dstcity` | `string` |
| `dstcountry` | `string` |
| `dstcountrycode` | `string` |
| `dstdomain` | `string` |
| `dstelevation` | `number` |
| `dsthost` | `string` |
| `dstiddcode` | `string` |
| `dstipv4` | `string` |
| `dstipv6` | `string` |
| `dstisp` | `string` |
| `dstlatitude` | `number` |
| `dstlocation` | `string` |
| `dstlongitude` | `number` |
| `dstmac` | `string` |
| `dstmcc` | `string` |
| `dstmnc` | `string` |
| `dstmobilebrand` | `string` |
| `dstnatrule` | `string` |
| `dstnetspeed` | `string` |
| `dstport` | `integer` |
| `dstregion` | `string` |
| `dstserver` | `ipv4` |
| `dsttimezone` | `string` |
| `dstusagetype` | `string` |
| `dstweatherstationcode` | `string` |
| `dstweatherstationname` | `string` |
| `dstzipcode` | `string` |
| `dstzone` | `string` |
| `duration` | `number` |
| `dynamic_indicators` | `string` |
| `enc_appdata_bytes` | `number` |
| `enc_appdata_packages` | `number` |
| `encodedmsg` | `string` |
| `encryption` | `string` |
| `encryption_level` | `string` |
| `endtime` | `string` |
| `endtimeutc` | `string` |
| `enriched` | `boolean` |
| `enrichment_error` | `string` |
| `enrichment_start` | `string` |
| `enrichment_status_txt` | `string` |
| `errorcode` | `integer` |
| `errormessage` | `string` |
| `escalateduration` | `integer` |
| `escalatetime` | `string` |
| `escalatetimeutc` | `string` |
| `established` | `boolean` |
| `eventid` | `string` |
| `eventlog` | `string` |
| `eventname` | `string` |
| `eventreceivedtime` | `date-time` |
| `eventtime` | `string` |
| `eventtimeutc` | `string` |
| `eventtype` | `string` |
| `evil_flag` | `boolean` |
| `evil_indicators` | `string` |
| `exceptionlvl` | `integer` |
| `exceptionmsg` | `string` |
| `exceptiontype` | `string` |
| `expirationtime` | `string` |
| `expirationtimeutc` | `string` |
| `extendedproperties` | `object` |
| `extension` | `string` |
| `extnatip` | `string` |
| `extnatipv6` | `ipv6` |
| `extracted` | `boolean` |
| `facility` | `string` |
| `family` | `string` |
| `file_accessed_time` | `string` |
| `file_created_time` | `string` |
| `file_enrichment_status` | `string` |
| `file_mime_type` | `string` |
| `file_modified_time` | `string` |
| `file_owner` | `string` |
| `file_signed` | `boolean` |
| `filedesc` | `string` |
| `fileid` | `string` |
| `filename` | `string` |
| `filepath` | `string` |
| `filepermission` | `string` |
| `filetype` | `string` |
| `filter` | `string` |
| `fingerprint` | `string` |
| `firstseen` | `string` |
| `firstseenutc` | `string` |
| `flagtype` | `string` |
| `flagval` | `string` |
| `force_log` | `boolean` |
| `foreigninterface` | `string` |
| `fqdn_nucleus_summary` | `string` |
| `from` | `string` |
| `function` | `string` |
| `fwdipv4` | `ipv4` |
| `fwdipv6` | `ipv6` |
| `gid` | `integer` |
| `group` | `string` |
| `groupdomain` | `string` |
| `groupsecurityid` | `string` |
| `gwipv4` | `ipv4` |
| `gwipv6` | `ipv6` |
| `handleid` | `integer` |
| `has_cert_table` | `boolean` |
| `has_debug_data` | `boolean` |
| `has_export_table` | `boolean` |
| `has_import_table` | `boolean` |
| `hash` | `string` |
| `hasMTAReport` | `boolean` |
| `heartbleed_detected` | `boolean` |
| `hierarchy` | `string` |
| `history` | `string` |
| `host_count` | `number` |
| `host_key` | `string` |
| `host_key_alg` | `string` |
| `host` | `string` |
| `hostname` | `string` |
| `hour` | `string` |
| `httpbody` | `string` |
| `httpmethod` | `string` |
| `hx_alert_id` | `number` |
| `icid` | `integer` |
| `impact` | `string` |
| `imphash` | `string` |
| `import_hash_count` | `number` |
| `info` | `string` |
| `infocode` | `string` |
| `infomsg` | `string` |
| `inreplyto` | `string` |
| `instance_id` | `string` |
| `instance_profile` | `string` |
| `instance_tags` | `object` |
| `instance_type` | `string` |
| `instanceid` | `string` |
| `integritylevel` | `string` |
| `intel_context` | `object` |
| `intel_context_unavailable` | `boolean` |
| `intel_match_observable` | `object` |
| `intel_matches` | `array` |
| `intelalertmessage` | `string` |
| `intelalertnotes` | `string` |
| `inteleventid` | `string` |
| `intelmalwarefamily` | `string` |
| `intelmatchclass` | `string` |
| `intelmatchfield` | `string` |
| `intelmatchtime` | `string` |
| `intelmatchvalue` | `string` |
| `intelmeta_cbid` | `integer` |
| `intelmeta_mid` | `integer` |
| `intelscore` | `string` |
| `inteltags` | `array` |
| `inteltype` | `integer` |
| `inteluuid` | `string` |
| `intelwhitelisted` | `object` |
| `interface` | `string` |
| `interfaceid` | `string` |
| `intnatip` | `string` |
| `iocname` | `string` |
| `iocnames` | `string` |
| `ip` | `string` |
| `ip_nucleus_summary` | `string` |
| `ipmask` | `string` |
| `ipv4` | `string` |
| `ipv6` | `string` |
| `is_64bit` | `boolean` |
| `is_exe` | `boolean` |
| `is_malware` | `boolean` |
| `isacquired` | `boolean` |
| `isorig` | `boolean` |
| `issuer` | `string` |
| `issuersubject` | `string` |
| `issuetime` | `string` |
| `issuetimeutc` | `string` |
| `job` | `string` |
| `jobid` | `string` |
| `kex_alg` | `string` |
| `keypair` | `string` |
| `keywords` | `string` |
| `language` | `string` |
| `last_auth_requested` | `string` |
| `last_originator_heartbeat_request_size` | `number` |
| `lastaccessedtime` | `string` |
| `lastaccessedtimeutc` | `string` |
| `lastalertid` | `string` |
| `lastmodifiedtime` | `string` |
| `lastmodifiedtimeutc` | `string` |
| `lastscannedtime` | `string` |
| `lastscannedtimeutc` | `string` |
| `lastseen` | `string` |
| `lastseenutc` | `string` |
| `lat` | `string` |
| `length` | `string` |
| `level` | `integer` |
| `linenumber` | `integer` |
| `local_resp` | `boolean` |
| `localinterface` | `string` |
| `localorig` | `boolean` |
| `logged` | `boolean` |
| `logonguid` | `string` |
| `logonid` | `string` |
| `logontype` | `string` |
| `logontypeid` | `integer` |
| `long` | `string` |
| `mac` | `string` |
| `mac_alg` | `string` |
| `macoui` | `string` |
| `mailbox` | `string` |
| `mailfrom` | `string` |
| `malwarefamily` | `string` |
| `malwarename` | `string` |
| `malwaretype` | `string` |
| `malwarevariant` | `string` |
| `manufacturer` | `string` |
| `mcube_list` | `string` |
| `md5` | `string` |
| `member` | `string` |
| `memberdomain` | `string` |
| `membersecurityid` | `string` |
| `message_id` | `string` |
| `meta_cb_c` | `string` |
| `meta_cb_cn` | `string` |
| `meta_cb_l` | `string` |
| `meta_cb_on` | `string` |
| `meta_cb_oun` | `string` |
| `meta_cb_st` | `string` |
| `meta_cbid` | `integer` |
| `meta_cbname` | `string` |
| `meta_cid` | `string` |
| `meta_cust_name` | `string` |
| `meta_i` | `string` |
| `meta_iid` | `integer` |
| `meta_mid` | `integer` |
| `meta_odt` | `string` |
| `meta_ohn` | `string` |
| `meta_omh` | `string` |
| `meta_oml` | `integer` |
| `meta_opri` | `string` |
| `meta_rrm` | `string` |
| `meta_rts` | `integer` |
| `meta_rule` | `string` |
| `meta_sip4` | `integer` |
| `meta_sip6` | `string` |
| `meta_sp` | `integer` |
| `meta_sts` | `integer` |
| `meta_ts` | `integer` |
| `metaclass` | `string` |
| `method` | `string` |
| `mid` | `integer` |
| `mimetype` | `string` |
| `minute` | `string` |
| `missingbytes` | `integer` |
| `mode` | `string` |
| `modifiedproperties` | `object` |
| `month` | `string` |
| `msg` | `string` |
| `msr_ruleids` | `array` |
| `network` | `string` |
| `network_connections` | `string` |
| `next_protocol` | `string` |
| `nick` | `string` |
| `node` | `string` |
| `notice` | `boolean` |
| `nuc_attribution_date` | `string` |
| `nuc_md5_attribution` | `string` |
| `number` | `integer` |
| `object` | `string` |
| `objectserver` | `string` |
| `objecttype` | `string` |
| `ocsp_response` | `string` |
| `ocsp_status` | `string` |
| `offset` | `string` |
| `old_period` | `integer` |
| `operationid` | `string` |
| `origin` | `string` |
| `original_company_name` | `string` |
| `original_description` | `string` |
| `original_file_name` | `string` |
| `originationtime` | `string` |
| `originationtimeutc` | `string` |
| `originator_heartbeats` | `number` |
| `os` | `string` |
| `overflowbytes` | `integer` |
| `packet_segment` | `string` |
| `packets` | `integer` |
| `packettype` | `string` |
| `page` | `integer` |
| `parameters` | `object` |
| `parentfileid` | `string` |
| `pargs` | `string` |
| `partition` | `string` |
| `passive` | `boolean` |
| `password` | `string` |
| `peak` | `number` |
| `pecreatedtime` | `string` |
| `pecreatedtimeutc` | `string` |
| `peer` | `string` |
| `pending_commands` | `string` |
| `perchg` | `number` |
| `period` | `integer` |
| `pid` | `integer` |
| `policy` | `string` |
| `policyid` | `string` |
| `portid` | `string` |
| `ppid` | `integer` |
| `pprocess` | `string` |
| `pprocessguid` | `string` |
| `pprocesspath` | `string` |
| `prevscore` | `number` |
| `printer` | `string` |
| `priority` | `string` |
| `privileges` | `string` |
| `privlevel` | `string` |
| `process` | `string` |
| `processguid` | `string` |
| `processid` | `string` |
| `processpath` | `string` |
| `product` | `string` |
| `profile` | `string` |
| `program` | `string` |
| `protocol` | `string` |
| `protocolver` | `string` |
| `protoid` | `integer` |
| `providerguid` | `string` |
| `proxied` | `string` |
| `proxydstipv4` | `ipv4` |
| `proxysrcipv4` | `string` |
| `proxystatuscode` | `integer` |
| `query` | `string` |
| `queryclass` | `integer` |
| `queryclassname` | `string` |
| `querytype` | `integer` |
| `querytypename` | `string` |
| `queue_id` | `string` |
| `rateavg` | `integer` |
| `rateid` | `string` |
| `ratemax` | `integer` |
| `rateval` | `integer` |
| `ratio` | `number` |
| `raw_facility` | `string` |
| `raw_facilityid` | `integer` |
| `raw_mid` | `string` |
| `raw_odt` | `string` |
| `raw_omsg` | `string` |
| `raw_pid` | `string` |
| `raw_pri` | `integer` |
| `raw_sdata` | `string` |
| `raw_sev` | `string` |
| `raw_sevid` | `integer` |
| `rawmsg` | `string` |
| `rawmsghostipv4` | `string` |
| `rawmsghostipv6` | `string` |
| `rawmsghostname` | `string` |
| `rawmsgid` | `string` |
| `rawmsgtimeutc` | `string` |
| `rawsrchostname` | `string` |
| `rcptto` | `string` |
| `rcvdbodybytes` | `integer` |
| `rcvdbytes` | `integer` |
| `rcvdfileid` | `string` |
| `rcvdipbytes` | `integer` |
| `rcvdmimetype` | `string` |
| `rcvdpackets` | `integer` |
| `ready` | `boolean` |
| `reason` | `string` |
| `receptorhostid` | `string` |
| `recordid` | `string` |
| `recursionavailable` | `boolean` |
| `recursiondesired` | `boolean` |
| `referenceid` | `string` |
| `referrer` | `string` |
| `referrer_domain` | `string` |
| `referrer_uri` | `string` |
| `region` | `string` |
| `regkey` | `string` |
| `regpath` | `string` |
| `regvalue` | `string` |
| `rejected` | `boolean` |
| `replay_datasource` | `string` |
| `reply_code` | `number` |
| `reply_msg` | `string` |
| `replyto` | `string` |
| `reportduration` | `integer` |
| `requestduration` | `number` |
| `requestid` | `string` |
| `requesttime` | `string` |
| `requesttimeutc` | `string` |
| `responder_heartbeats` | `number` |
| `response` | `string` |
| `responsecode` | `integer` |
| `responsecodename` | `string` |
| `restrictedsidcount` | `string` |
| `result` | `string` |
| `resumed` | `boolean` |
| `rid` | `integer` |
| `risk` | `string` |
| `risklevel` | `integer` |
| `roleid` | `string` |
| `rt_version` | `object` |
| `rule` | `string` |
| `rulecat` | `string` |
| `ruleid` | `string` |
| `satori_blacklist` | `string` |
| `saw_query` | `boolean` |
| `saw_reply` | `boolean` |
| `score` | `number` |
| `second` | `string` |
| `security_groups` | `object` |
| `seenbytes` | `integer` |
| `sensor` | `string` |
| `sentbodybytes` | `integer` |
| `sentbytes` | `integer` |
| `sentfileid` | `string` |
| `sentipbytes` | `integer` |
| `sentmimetype` | `string` |
| `sentpackets` | `integer` |
| `serial` | `string` |
| `server` | `string` |
| `server_depth` | `number` |
| `serveripv4` | `ipv4` |
| `serveripv6` | `ipv6` |
| `serverport` | `string` |
| `serverstatuscode` | `integer` |
| `servervars` | `string` |
| `service` | `string` |
| `serviceid` | `string` |
| `sessionid` | `string` |
| `sessionname` | `string` |
| `sessiontype` | `string` |
| `severity` | `string` |
| `severityvalue` | `integer` |
| `sha1` | `string` |
| `sha256` | `string` |
| `sha512` | `string` |
| `signature` | `string` |
| `signed` | `boolean` |
| `site` | `string` |
| `size` | `string` |
| `sizeinram` | `number` |
| `sizeondisk` | `number` |
| `slot` | `string` |
| `snort_alert` | `string` |
| `source` | `string` |
| `sourceclass` | `string` |
| `sourcemodulename` | `string` |
| `sourcemoduletype` | `string` |
| `srcareacode` | `string` |
| `srcasn` | `string` |
| `srcasorg` | `string` |
| `srccity` | `string` |
| `srccountry` | `string` |
| `srccountrycode` | `string` |
| `srcdomain` | `string` |
| `srcelevation` | `number` |
| `srchost` | `string` |
| `srciddcode` | `string` |
| `srcipv4` | `string` |
| `srcipv6` | `string` |
| `srcisp` | `string` |
| `srclatitude` | `number` |
| `srclocation` | `string` |
| `srclongitude` | `string` |
| `srcmac` | `string` |
| `srcmcc` | `string` |
| `srcmnc` | `string` |
| `srcmobilebrand` | `string` |
| `srcnatrule` | `string` |
| `srcnetspeed` | `string` |
| `srcport` | `integer` |
| `srcregion` | `string` |
| `srcserver` | `ipv4` |
| `srctimezone` | `string` |
| `srcusagetype` | `string` |
| `srcweatherstationcode` | `string` |
| `srcweatherstationname` | `string` |
| `srczipcode` | `string` |
| `srczone` | `string` |
| `ssdeep` | `string` |
| `ssid` | `string` |
| `ssl` | `boolean` |
| `starttime` | `string` |
| `starttimeutc` | `string` |
| `static_indicators` | `string` |
| `stationid` | `string` |
| `status` | `string` |
| `status_changed_at_time` | `string` |
| `statuscode` | `integer` |
| `statusmsg` | `string` |
| `strings` | `string` |
| `stringval` | `string` |
| `subfiletype` | `string` |
| `subject` | `string` |
| `submit_to_satori_at_time` | `string` |
| `submitted_by` | `string` |
| `submitted_by_name` | `string` |
| `submittedAt` | `string` |
| `subnet_id` | `string` |
| `subsystem` | `string` |
| `subtype` | `string` |
| `suppressfor` | `integer` |
| `system` | `string` |
| `tags` | `string` |
| `target` | `string` |
| `targetdomain` | `string` |
| `targethost` | `string` |
| `targetip` | `string` |
| `targetipv6` | `ipv6` |
| `targetlogonid` | `string` |
| `targetusername` | `string` |
| `targetusersecurityid` | `string` |
| `task` | `string` |
| `tcp_details` | `object` |
| `technique` | `string` |
| `threadid` | `string` |
| `threat` | `string` |
| `threshold` | `number` |
| `timedout` | `boolean` |
| `timezone` | `string` |
| `to` | `string` |
| `total_bytes` | `number` |
| `totalanswers` | `integer` |
| `totalpages` | `integer` |
| `totalreplies` | `integer` |
| `track_address` | `number` |
| `transactionid` | `string` |
| `transdsthost` | `string` |
| `transdstip` | `string` |
| `transdstport` | `integer` |
| `transsrchost` | `string` |
| `transsrcip` | `string` |
| `transsrcport` | `integer` |
| `trigger_details` | `string` |
| `truncationbit` | `boolean` |
| `ttl` | `string` |
| `tty` | `string` |
| `tunnel_type` | `string` |
| `tunnelparents` | `string` |
| `type` | `integer` |
| `type_details` | `object` |
| `uid` | `integer` |
| `unparsed_version` | `string` |
| `uri` | `string` |
| `uri_parsed` | `string` |
| `url` | `string` |
| `useragent` | `string` |
| `usercheck` | `string` |
| `usercheckid` | `string` |
| `userchecklvl` | `string` |
| `usercheckname` | `string` |
| `username` | `string` |
| `usersecurityid` | `string` |
| `uses_aslr` | `boolean` |
| `uses_code_integrity` | `boolean` |
| `uses_dep` | `boolean` |
| `uses_seh` | `boolean` |
| `uuid` | `string` |
| `version` | `string` |
| `vhost` | `string` |
| `virtualdomain` | `string` |
| `virtualhost` | `string` |
| `virus` | `string` |
| `vlan` | `integer` |
| `vlandesc` | `string` |
| `vlanname` | `string` |
| `volume` | `string` |
| `vpc` | `string` |
| `vt_first_seen` | `string` |
| `vt_ratio` | `string` |
| `webclient` | `string` |
| `webclienttype` | `string` |
| `webserver` | `string` |
| `webservertype` | `string` |
| `weight` | `number` |
| `whitelist_info` | `string` |
| `workstation` | `string` |
| `x509` | `string` |
| `xfwdforip` | `string` |
| `yara_hits` | `string` |
| `year` | `string` |
| `zone` | `string` |

### 3.1 ドメイン／ホスト関連KEY

`domain` / `vhost` / `virtualhost` / `virtualdomain` / `host` / `hostname` は、すべて独立したTaxonomy KEYである。受信JSONに同名KEYが存在すれば、それぞれのKEY:VALUEをそのまま機能対象として扱う。

- `vhost`: ログ送信元が `vhost` として明示した仮想ホスト名
- `host`: ログ送信元が `host` として明示したホスト名・ホスト識別値

これらを相互変換・コピー・補完してはならない。例えば `vhost` を `virtualhost` に読み替えず、`host` を `hostname` に読み替えない。

## 4. LogSeeker拡張KEY
| KEY | 型 | 意味 |
|---|---|---|
| `virtualdomain` | `string` | Web/メール等の仮想ドメイン名。例: example.com。`domain` とは別フィールドとして扱い、LogSeekerが相互変換しない。 |
| `virtualhost` | `string` | Webサーバー等で設定された仮想ホスト名。FQDN、サーバー設定名、仮想ホスト識別名を格納する。 |
| `srcasn` | `string` | ログ送信元が送信元IPのASNをpayloadとして明示する場合に使用する受信KEY。LogSeekerがGeoIP解析で生成したASNはpayloadへ `srcasn` として追加せず、別の派生メタデータとして扱う。 |
| `srcasorg` | `string` | ログ送信元が送信元IPのAS組織名をpayloadとして明示する場合に使用する受信KEY。LogSeekerがGeoIP解析で生成したAS組織名はpayloadへ `srcasorg` として追加せず、別の派生メタデータとして扱う。 |
| `dstasn` | `string` | 宛先IPに対応する自律システム番号（ASN）。 |
| `dstasorg` | `string` | 宛先IPのASNに対応する組織名。 |

Webサイトの識別では、ログ送信元が `domain`、`virtualdomain`、`virtualhost` 等のどのKEYを使うかは環境・送信設定によって異なり得る。LogSeekerは一つのKEYへ強制統合しない。

LogSeekerにおける `domain` は、受信JSONで `domain` として明示された一般ドメイン値として扱う。Windows/AD等のアカウントドメインは `accountdomain` 等のより具体的なKEYを推奨する。

## 5. `class` の扱い

**`class`（クラス）とは、収集されたログやイベントの種類・ログソースを識別するための標準化された識別子である。**

`class` は本書の「標準タクソノミー 全KEY」に含まれる `string` 型のTaxonomy KEYである。Class名は `class` のVALUEそのものであり、別のClassマスター一覧は持たない。

例:

```json
{ "class": "web_access" }
```

```json
{ "class": "skysea" }
```

この場合のクラス名は、それぞれ `web_access`、`skysea` である。

ログ送信元は原則としてJSON生成時に `class` を設定する。Syslog、Webアクセスログ、製品独自形式等をNXLog等でJSONへ変換する場合も、必要なクラス名を `class` のVALUEとして設定してから送信する。

LogSeekerは受信した `class` のVALUEをそのまま使用する。別のクラス名への読み替え、変換、推測、補完は行わない。`class` が存在しない場合も `unknown` 等を自動追加しない。

`web_access`、`web_error`、`linux`、`audit`、`windows_event`、`skysea` 等はClass名の**例**であり、固定リストや許可リストではない。

## 6. Class VALUE別の参考例

**この章は参考例であり、Class名を決める規則ではない。**

Taxonomy KEY一覧が先に存在し、`class` のVALUEはKEYの所属先を決めない。以下は、ログ送信元がJSONを作成するときに「`class` をこのVALUEにするログでは、例えばこのKEYを使うと分かりやすい」という参考例である。

**他のKEYの存在からClass名を決めてはならない。** 例えば `accountname` が受信payloadに存在しても、それだけで `web_access`、`windows_event`、`audit` 等にはならない。クラス名は受信JSONの `class` VALUEである。

Class VALUE別の参考KEY例:

| Class | 参考KEY例 |
|---|---|
| `web_access` | `class`, `eventtime`, `srcipv4` / `srcipv6`, `httpmethod`, `uri`, `statuscode`, `domain`, `virtualhost`, `useragent` 等 |
| `web_error` | `class`, `eventtime`, `description`, `severity`, `hostname`, `domain`, `srcipv4` / `srcipv6` 等 |
| `linux` | `class`, `eventtime`, `hostname`, `description`, `severity`, `service`, `srcipv4` / `srcipv6`, `username` 等 |
| `audit` | `class`, `eventtime`, `description`, `hostname`, `action`, `result`, `service`, `srcipv4` / `srcipv6`, `accountname` 等 |
| `windows_event` | `class`, `eventtime`, `eventid`, `eventlog`, `hostname`, `description`, `accountname`, `accountdomain` 等 |
| `unknown` | `class`, `eventtime`, `description`, `hostname` 等、受信payloadに実在するTaxonomy KEY |

この表にないTaxonomy KEYでも、全KEY一覧に存在し、受信payloadに同名KEYがあれば機能対象にできる。逆に、参考例にあるKEYが存在してもクラス名は決まらない。クラス名は `class` のVALUEである。

NXLog等の送信設定例は `examples/` 配下等で別途示してよい。送信設定例は送信JSONを作るための参考であり、LogSeekerが受信後にpayloadを書き換える処理ではない。

### 6.1 参考例: `web_access`

最近の実ログでは、イベント時刻、送信元IP（IPv4/IPv6）、URLパス、HTTPメソッド、HTTPステータス、必要に応じてクエリ文字列を確認できる。通常のWebアクセスログに仮想ドメインや仮想ホストが含まれない場合は、NXLog等のログ送信元がJSON生成時に `virtualdomain` / `virtualhost` を明示設定する。

`username` / `accountname` を含める例もある。Basic認証等によりWebアクセスログまたはログ送信元が認証ユーザーを明示的に取得できる場合だけ利用し、通常の匿名Webアクセスで設定を要求しない。

| KEY | 表示名 | 型 | 初期表示 | 用途 |
| --- | --- | --- | --- | --- |
| `class` | クラス | `string` | 表示 | ログやイベントの種類・ログソースを識別するクラス名。ログ送信元が設定したVALUEをそのまま使用する。 |
| `eventtime` | イベント時刻 | `string` | 表示 | イベント発生時刻 |
| `eventtimeutc` | イベント時刻(UTC) | `string` | 非表示 | イベント発生時刻のUTC表現 |
| `category` | カテゴリ | `string` | 表示 | イベントの分類カテゴリ |
| `action` | アクション | `string` | 表示 | イベントで発生/実行された動作 |
| `result` | 結果 | `string` | 表示 | success/failure等の最終結果 |
| `severity` | 重大度 | `string` | 表示 | イベント重大度 |
| `severityvalue` | 重大度値 | `integer` | 非表示 | 数値重大度 |
| `description` | メッセージ | `string` | 表示 | 原文またはイベント説明 |
| `reason` | 理由 | `string` | 非表示 | 失敗・拒否・警告等の理由 |
| `srcipv4` | 送信元IPv4 | `string` | 表示 | 送信元IPv4アドレス |
| `srcipv6` | 送信元IPv6 | `string` | 表示 | 送信元IPv6アドレス |
| `srchost` | 送信元ホスト | `string` | 非表示 | 送信元ホスト名 |
| `srcport` | 送信元ポート | `integer` | 非表示 | 送信元ポート番号 |
| `srccountry` | 送信元国 | `string` | 非表示 | 送信元IPの国 |
| `srccountrycode` | 送信元国コード | `string` | 非表示 | 送信元IPの国コード |
| `srcasn` | 送信元ASN | `string` | 非表示 | 送信元IPのASN |
| `srcasorg` | 送信元AS組織 | `string` | 非表示 | 送信元IPのAS組織名 |
| `dstipv4` | 宛先IPv4 | `string` | 非表示 | 宛先IPv4アドレス |
| `dstipv6` | 宛先IPv6 | `string` | 非表示 | 宛先IPv6アドレス |
| `dsthost` | 宛先ホスト | `string` | 非表示 | 宛先ホスト名 |
| `dstport` | 宛先ポート | `integer` | 非表示 | 宛先ポート番号 |
| `dstcountry` | 宛先国 | `string` | 非表示 | 宛先IPの国 |
| `dstcountrycode` | 宛先国コード | `string` | 非表示 | 宛先IPの国コード |
| `dstasn` | 宛先ASN | `string` | 非表示 | 宛先IPのASN |
| `dstasorg` | 宛先AS組織 | `string` | 非表示 | 宛先IPのAS組織名 |
| `domain` | ドメイン | `string` | 非表示 | 送信元が `domain` として明示したドメイン名。関連KEYとは別フィールドのまま共存できる。 |
| `vhost` | VHost | `string` | 非表示 | ログ送信元が `vhost` として明示した仮想ホスト名 |
| `virtualdomain` | 仮想ドメイン | `string` | 表示 | Web/メール等の仮想ドメイン名 |
| `virtualhost` | 仮想ホスト | `string` | 非表示 | Webサーバー等の仮想ホスト名 |
| `host` | ホスト | `string` | 非表示 | ログ送信元が `host` として明示したホスト名・ホスト識別値 |
| `webserver` | Webサーバー | `string` | 非表示 | Webサーバー製品/識別名 |
| `server` | サーバー | `string` | 非表示 | サーバー名/識別情報 |
| `serveripv4` | サーバーIPv4 | `ipv4` | 非表示 | サーバーIPv4アドレス |
| `serveripv6` | サーバーIPv6 | `ipv6` | 非表示 | サーバーIPv6アドレス |
| `serverport` | サーバーポート | `string` | 非表示 | サーバーポート番号 |
| `protocol` | プロトコル | `string` | 非表示 | HTTP/TCP/SSH等のプロトコル |
| `protocolver` | プロトコルバージョン | `string` | 非表示 | プロトコルのバージョン |
| `httpmethod` | HTTPメソッド | `string` | 表示 | GET/POST/PUT等 |
| `uri` | URI | `string` | 表示 | 要求されたURI |
| `uri_parsed` | 正規化URI | `string` | 非表示 | 正規化したURI |
| `url` | URL | `string` | 非表示 | ドメインを含む完全URL |
| `query` | クエリ | `string` | 非表示 | Web/DNS/DB等のクエリ文字列 |
| `statuscode` | ステータスコード | `integer` | 表示 | HTTP等の数値ステータスコード |
| `statusmsg` | ステータスメッセージ | `string` | 非表示 | ステータスに対応するメッセージ |
| `bytes` | バイト数 | `integer` | 非表示 | 方向不明の転送バイト数 |
| `sentbytes` | 送信バイト数 | `integer` | 非表示 | 送信元から送信した総バイト数 |
| `rcvdbytes` | 受信バイト数 | `integer` | 非表示 | 宛先が受信した総バイト数 |
| `sentbodybytes` | 送信Bodyバイト数 | `integer` | 非表示 | HTTP request body等のバイト数 |
| `rcvdbodybytes` | 受信Bodyバイト数 | `integer` | 非表示 | HTTP response body等のバイト数 |
| `referrer` | Referer | `string` | 非表示 | HTTP Referer値 |
| `referrer_domain` | Refererドメイン | `string` | 非表示 | HTTP Refererのドメイン |
| `referrer_uri` | Referer URI | `string` | 非表示 | HTTP RefererのURI |
| `useragent` | User-Agent | `string` | 非表示 | HTTPクライアントUser-Agent |
| `xfwdforip` | X-Forwarded-For | `string` | 非表示 | X-Forwarded-Forヘッダー値 |
| `mimetype` | MIMEタイプ | `string` | 非表示 | コンテンツMIMEタイプ |
| `requestid` | リクエストID | `string` | 非表示 | リクエスト識別子 |
| `sessionid` | セッションID | `string` | 非表示 | セッション識別子 |
| `username` | ユーザー名 | `string` | 非表示 | Basic認証等で明示的に取得できる場合のユーザー名。任意。 |
| `accountname` | アカウント名 | `string` | 非表示 | Basic認証等で明示的に取得できる場合のアカウント名。任意。 |

### 6.2 参考例: `web_error`

最近の実ログでは、主にイベント時刻と自由形式メッセージを確認できる。NXLog等が解析してJSON化できる追加項目は利用してよいが、LogSeekerが受信後に不足値を推測して追加してはならない。

| KEY | 表示名 | 型 | 初期表示 | 用途 |
| --- | --- | --- | --- | --- |
| `class` | クラス | `string` | 表示 | ログやイベントの種類・ログソースを識別するクラス名。ログ送信元が設定したVALUEをそのまま使用する。 |
| `eventtime` | イベント時刻 | `string` | 表示 | イベント発生時刻 |
| `eventtimeutc` | イベント時刻(UTC) | `string` | 非表示 | イベント発生時刻のUTC表現 |
| `category` | カテゴリ | `string` | 表示 | イベントの分類カテゴリ |
| `action` | アクション | `string` | 表示 | イベントで発生/実行された動作 |
| `result` | 結果 | `string` | 表示 | success/failure等の最終結果 |
| `severity` | 重大度 | `string` | 表示 | イベント重大度 |
| `severityvalue` | 重大度値 | `integer` | 非表示 | 数値重大度 |
| `description` | メッセージ | `string` | 表示 | 原文またはイベント説明 |
| `reason` | 理由 | `string` | 非表示 | 失敗・拒否・警告等の理由 |
| `errormessage` | エラーメッセージ | `string` | 非表示 | エラーコードに対応する文字列や、エラー内容を示す専用メッセージ |
| `eventid` | イベントID | `string` | 表示 | イベント固有ID/WindowsイベントID等 |
| `eventtype` | イベント種別 | `string` | 非表示 | ログソースが示すイベント種別 |
| `hostname` | ホスト名 | `string` | 表示 | 方向が不明なホスト名 |
| `domain` | ドメイン | `string` | 非表示 | 送信元が `domain` として明示したドメイン名。関連KEYへ変換しない。 |
| `vhost` | VHost | `string` | 非表示 | ログ送信元が `vhost` として明示した仮想ホスト名 |
| `virtualdomain` | 仮想ドメイン | `string` | 表示 | Web/メール等の仮想ドメイン名 |
| `virtualhost` | 仮想ホスト | `string` | 非表示 | Webサーバー等の仮想ホスト名 |
| `host` | ホスト | `string` | 非表示 | ログ送信元が `host` として明示したホスト名・ホスト識別値 |
| `webserver` | Webサーバー | `string` | 非表示 | Webサーバー製品/識別名 |
| `server` | サーバー | `string` | 非表示 | サーバー名/識別情報 |
| `serveripv4` | サーバーIPv4 | `ipv4` | 非表示 | サーバーIPv4アドレス |
| `serveripv6` | サーバーIPv6 | `ipv6` | 非表示 | サーバーIPv6アドレス |
| `serverport` | サーバーポート | `string` | 非表示 | サーバーポート番号 |
| `srcipv4` | 送信元IPv4 | `string` | 表示 | 送信元IPv4アドレス |
| `srcipv6` | 送信元IPv6 | `string` | 表示 | 送信元IPv6アドレス |
| `srcport` | 送信元ポート | `integer` | 非表示 | 送信元ポート番号 |
| `dstipv4` | 宛先IPv4 | `string` | 非表示 | 宛先IPv4アドレス |
| `dstipv6` | 宛先IPv6 | `string` | 非表示 | 宛先IPv6アドレス |
| `dstport` | 宛先ポート | `integer` | 非表示 | 宛先ポート番号 |
| `protocol` | プロトコル | `string` | 非表示 | HTTP/TCP/SSH等のプロトコル |
| `httpmethod` | HTTPメソッド | `string` | 表示 | GET/POST/PUT等 |
| `uri` | URI | `string` | 表示 | 要求されたURI |
| `url` | URL | `string` | 非表示 | ドメインを含む完全URL |
| `query` | クエリ | `string` | 非表示 | Web/DNS/DB等のクエリ文字列 |
| `statuscode` | ステータスコード | `integer` | 表示 | HTTP等の数値ステータスコード |
| `statusmsg` | ステータスメッセージ | `string` | 非表示 | ステータスに対応するメッセージ |
| `service` | サービス | `string` | 表示 | サービス/デーモン/Windowsサービス名 |
| `process` | プロセス | `string` | 表示 | プロセス名/説明 |
| `processid` | プロセスID | `string` | 非表示 | プロセス識別子 |
| `pid` | PID | `integer` | 非表示 | OSプロセスID |
| `ppid` | 親PID | `integer` | 非表示 | 親プロセスID |
| `processpath` | プロセスパス | `string` | 非表示 | 実行ファイルのパス |
| `pprocess` | 親プロセス | `string` | 非表示 | 親プロセス名 |
| `pprocesspath` | 親プロセスパス | `string` | 非表示 | 親プロセスのパス |
| `username` | ユーザー名 | `string` | 表示 | イベント内のユーザー名 |
| `accountname` | アカウント名 | `string` | 表示 | 認証対象/主体のアカウント名 |

### 6.3 参考例: `linux`

最近の実ログでは、ホスト名またはデバイス名、サービス、重大度、メッセージ、および該当イベントのSSH送信元IPを確認できる。

| KEY | 表示名 | 型 | 初期表示 | 用途 |
| --- | --- | --- | --- | --- |
| `class` | クラス | `string` | 表示 | ログやイベントの種類・ログソースを識別するクラス名。ログ送信元が設定したVALUEをそのまま使用する。 |
| `eventtime` | イベント時刻 | `string` | 表示 | イベント発生時刻 |
| `eventtimeutc` | イベント時刻(UTC) | `string` | 非表示 | イベント発生時刻のUTC表現 |
| `category` | カテゴリ | `string` | 表示 | イベントの分類カテゴリ |
| `action` | アクション | `string` | 表示 | イベントで発生/実行された動作 |
| `result` | 結果 | `string` | 表示 | success/failure等の最終結果 |
| `severity` | 重大度 | `string` | 表示 | イベント重大度 |
| `severityvalue` | 重大度値 | `integer` | 非表示 | 数値重大度 |
| `description` | メッセージ | `string` | 表示 | 原文またはイベント説明 |
| `reason` | 理由 | `string` | 非表示 | 失敗・拒否・警告等の理由 |
| `eventid` | イベントID | `string` | 表示 | イベント固有ID/WindowsイベントID等 |
| `eventtype` | イベント種別 | `string` | 非表示 | ログソースが示すイベント種別 |
| `hostname` | ホスト名 | `string` | 表示 | 方向が不明なホスト名 |
| `devicename` | デバイス名 | `string` | 非表示 | ログが示すデバイス名 |
| `srcipv4` | 送信元IPv4 | `string` | 表示 | 送信元IPv4アドレス |
| `srcipv6` | 送信元IPv6 | `string` | 表示 | 送信元IPv6アドレス |
| `srcport` | 送信元ポート | `integer` | 非表示 | 送信元ポート番号 |
| `dstipv4` | 宛先IPv4 | `string` | 非表示 | 宛先IPv4アドレス |
| `dstipv6` | 宛先IPv6 | `string` | 非表示 | 宛先IPv6アドレス |
| `dstport` | 宛先ポート | `integer` | 非表示 | 宛先ポート番号 |
| `protocol` | プロトコル | `string` | 非表示 | HTTP/TCP/SSH等のプロトコル |
| `service` | サービス | `string` | 表示 | サービス/デーモン/Windowsサービス名 |
| `serviceid` | サービスID | `string` | 非表示 | サービス識別子 |
| `username` | ユーザー名 | `string` | 表示 | イベント内のユーザー名 |
| `uid` | UID | `integer` | 非表示 | OS/アプリケーションのユーザーID |
| `gid` | GID | `integer` | 非表示 | グループID |
| `accountname` | アカウント名 | `string` | 表示 | 認証対象/主体のアカウント名 |
| `accountdomain` | アカウントドメイン | `string` | 表示 | アカウントが属するドメイン |
| `sessionid` | セッションID | `string` | 非表示 | セッション識別子 |
| `authmethod` | 認証方式 | `string` | 非表示 | 認証方式/プロトコル |
| `process` | プロセス | `string` | 表示 | プロセス名/説明 |
| `processid` | プロセスID | `string` | 非表示 | プロセス識別子 |
| `pid` | PID | `integer` | 非表示 | OSプロセスID |
| `ppid` | 親PID | `integer` | 非表示 | 親プロセスID |
| `processpath` | プロセスパス | `string` | 非表示 | 実行ファイルのパス |
| `pprocess` | 親プロセス | `string` | 非表示 | 親プロセス名 |
| `pprocesspath` | 親プロセスパス | `string` | 非表示 | 親プロセスのパス |
| `target` | 対象 | `string` | 非表示 | 操作対象のユーザー/サービス/オブジェクト |
| `targethost` | 対象ホスト | `string` | 非表示 | 操作対象ホスト |
| `targetip` | 対象IPv4 | `string` | 非表示 | 操作対象IPv4 |
| `targetipv6` | 対象IPv6 | `ipv6` | 非表示 | 操作対象IPv6 |
| `targetusername` | 対象ユーザー | `string` | 表示 | 操作対象ユーザー名 |

### 6.4 参考例: `audit`

最近の実ログでは、監査アクション、結果、サービス、該当イベントの送信元IP、自由形式の監査メッセージを確認できる。実際のJSONパスは、LogSeekerが受信した生payloadを確認して確定する。

| KEY | 表示名 | 型 | 初期表示 | 用途 |
| --- | --- | --- | --- | --- |
| `class` | クラス | `string` | 表示 | ログやイベントの種類・ログソースを識別するクラス名。ログ送信元が設定したVALUEをそのまま使用する。 |
| `eventtime` | イベント時刻 | `string` | 表示 | イベント発生時刻 |
| `eventtimeutc` | イベント時刻(UTC) | `string` | 非表示 | イベント発生時刻のUTC表現 |
| `category` | カテゴリ | `string` | 表示 | イベントの分類カテゴリ |
| `action` | アクション | `string` | 表示 | イベントで発生/実行された動作 |
| `result` | 結果 | `string` | 表示 | success/failure等の最終結果 |
| `severity` | 重大度 | `string` | 表示 | イベント重大度 |
| `severityvalue` | 重大度値 | `integer` | 非表示 | 数値重大度 |
| `description` | メッセージ | `string` | 表示 | 原文またはイベント説明 |
| `reason` | 理由 | `string` | 非表示 | 失敗・拒否・警告等の理由 |
| `eventid` | イベントID | `string` | 表示 | イベント固有ID/WindowsイベントID等 |
| `eventtype` | イベント種別 | `string` | 非表示 | ログソースが示すイベント種別 |
| `audititemid` | 監査項目ID | `string` | 非表示 | 監査項目識別子 |
| `hostname` | ホスト名 | `string` | 表示 | 方向が不明なホスト名 |
| `srcipv4` | 送信元IPv4 | `string` | 表示 | 送信元IPv4アドレス |
| `srcipv6` | 送信元IPv6 | `string` | 表示 | 送信元IPv6アドレス |
| `srcport` | 送信元ポート | `integer` | 非表示 | 送信元ポート番号 |
| `dstipv4` | 宛先IPv4 | `string` | 非表示 | 宛先IPv4アドレス |
| `dstipv6` | 宛先IPv6 | `string` | 非表示 | 宛先IPv6アドレス |
| `dstport` | 宛先ポート | `integer` | 非表示 | 宛先ポート番号 |
| `protocol` | プロトコル | `string` | 非表示 | HTTP/TCP/SSH等のプロトコル |
| `service` | サービス | `string` | 表示 | サービス/デーモン/Windowsサービス名 |
| `username` | ユーザー名 | `string` | 表示 | イベント内のユーザー名 |
| `uid` | UID | `integer` | 非表示 | OS/アプリケーションのユーザーID |
| `gid` | GID | `integer` | 非表示 | グループID |
| `accountname` | アカウント名 | `string` | 表示 | 認証対象/主体のアカウント名 |
| `accountdomain` | アカウントドメイン | `string` | 表示 | アカウントが属するドメイン |
| `sessionid` | セッションID | `string` | 非表示 | セッション識別子 |
| `authmethod` | 認証方式 | `string` | 非表示 | 認証方式/プロトコル |
| `process` | プロセス | `string` | 表示 | プロセス名/説明 |
| `processid` | プロセスID | `string` | 非表示 | プロセス識別子 |
| `pid` | PID | `integer` | 非表示 | OSプロセスID |
| `ppid` | 親PID | `integer` | 非表示 | 親プロセスID |
| `processpath` | プロセスパス | `string` | 非表示 | 実行ファイルのパス |
| `pprocess` | 親プロセス | `string` | 非表示 | 親プロセス名 |
| `pprocesspath` | 親プロセスパス | `string` | 非表示 | 親プロセスのパス |
| `target` | 対象 | `string` | 非表示 | 操作対象のユーザー/サービス/オブジェクト |
| `targethost` | 対象ホスト | `string` | 非表示 | 操作対象ホスト |
| `targetip` | 対象IPv4 | `string` | 非表示 | 操作対象IPv4 |
| `targetipv6` | 対象IPv6 | `ipv6` | 非表示 | 操作対象IPv6 |
| `targetusername` | 対象ユーザー | `string` | 表示 | 操作対象ユーザー名 |
| `requestid` | リクエストID | `string` | 非表示 | リクエスト識別子 |

### 6.5 参考例: `windows_event`

最近の実ログでは、WindowsイベントID、Securityログ、ホスト、イベント内アカウント、メッセージを確認できる。イベントIDによっては、メッセージ内にアカウントドメイン／アカウント名、ログオンID／ログオンタイプ、プロセス情報、ネットワーク情報が含まれる。実際のJSONパスは、LogSeekerが受信した生payloadを確認して確定する。

| KEY | 表示名 | 型 | 初期表示 | 用途 |
| --- | --- | --- | --- | --- |
| `class` | クラス | `string` | 表示 | ログやイベントの種類・ログソースを識別するクラス名。ログ送信元が設定したVALUEをそのまま使用する。 |
| `eventtime` | イベント時刻 | `string` | 表示 | イベント発生時刻 |
| `eventtimeutc` | イベント時刻(UTC) | `string` | 非表示 | イベント発生時刻のUTC表現 |
| `category` | カテゴリ | `string` | 表示 | イベントの分類カテゴリ |
| `action` | アクション | `string` | 表示 | イベントで発生/実行された動作 |
| `result` | 結果 | `string` | 表示 | success/failure等の最終結果 |
| `severity` | 重大度 | `string` | 表示 | イベント重大度 |
| `severityvalue` | 重大度値 | `integer` | 非表示 | 数値重大度 |
| `description` | メッセージ | `string` | 表示 | 原文またはイベント説明 |
| `reason` | 理由 | `string` | 非表示 | 失敗・拒否・警告等の理由 |
| `eventid` | イベントID | `string` | 表示 | イベント固有ID/WindowsイベントID等 |
| `eventlog` | イベントログ | `string` | 表示 | Windows Event Logチャネル/ログ名 |
| `eventtype` | イベント種別 | `string` | 非表示 | ログソースが示すイベント種別 |
| `recordid` | レコードID | `string` | 非表示 | Windows Event レコードID |
| `providerguid` | プロバイダーGUID | `string` | 非表示 | WindowsイベントプロバイダーGUID |
| `task` | タスク | `string` | 非表示 | WindowsイベントTask |
| `keywords` | キーワード | `string` | 非表示 | WindowsイベントKeywords |
| `hostname` | ホスト名 | `string` | 表示 | 方向が不明なホスト名 |
| `devicename` | デバイス名 | `string` | 非表示 | ログが示すデバイス名 |
| `service` | サービス | `string` | 表示 | サービス/デーモン/Windowsサービス名 |
| `accountname` | アカウント名 | `string` | 表示 | 認証対象/主体のアカウント名 |
| `accountdomain` | アカウントドメイン | `string` | 表示 | アカウントが属するドメイン |
| `username` | ユーザー名 | `string` | 表示 | イベント内のユーザー名 |
| `usersecurityid` | ユーザーSID | `string` | 非表示 | WindowsユーザーのSID |
| `callingusername` | 呼出元ユーザー | `string` | 非表示 | Windowsイベント等の呼出元ユーザー |
| `callingdomain` | 呼出元ドメイン | `string` | 非表示 | Windowsイベント等の呼出元ドメイン |
| `callingusersecurityid` | 呼出元ユーザーSID | `string` | 非表示 | Windowsイベント等の呼出元SID |
| `callinglogonid` | 呼出元ログオンID | `string` | 非表示 | Windowsイベント等の呼出元ログオンID |
| `callingsrcip` | 呼出元IP | `string` | 非表示 | Windowsイベント等の呼出元IPv4 |
| `callingsrcipv6` | 呼出元IPv6 | `ipv6` | 非表示 | Windowsイベント等の呼出元IPv6 |
| `targetusername` | 対象ユーザー | `string` | 表示 | 操作対象ユーザー名 |
| `targetdomain` | 対象ドメイン | `string` | 非表示 | 操作対象ドメイン |
| `targetusersecurityid` | 対象ユーザーSID | `string` | 非表示 | 操作対象SID |
| `targetlogonid` | 対象ログオンID | `string` | 非表示 | 操作対象ログオンID |
| `targethost` | 対象ホスト | `string` | 非表示 | 操作対象ホスト |
| `targetip` | 対象IPv4 | `string` | 非表示 | 操作対象IPv4 |
| `targetipv6` | 対象IPv6 | `ipv6` | 非表示 | 操作対象IPv6 |
| `logonid` | ログオンID | `string` | 非表示 | WindowsログオンID |
| `logonguid` | ログオンGUID | `string` | 非表示 | WindowsログオンGUID |
| `logontype` | ログオン種別 | `string` | 非表示 | Windowsログオン種別(文字列) |
| `logontypeid` | ログオンタイプ | `integer` | 表示 | WindowsログオンタイプID |
| `workstation` | ワークステーション | `string` | 非表示 | Windowsイベントのワークステーション名 |
| `authmethod` | 認証方式 | `string` | 非表示 | 認証方式/プロトコル |
| `privileges` | 特権 | `string` | 非表示 | Windowsで付与/保持された特権 |
| `process` | プロセス | `string` | 表示 | プロセス名/説明 |
| `processid` | プロセスID | `string` | 非表示 | プロセス識別子 |
| `pid` | PID | `integer` | 非表示 | OSプロセスID |
| `ppid` | 親PID | `integer` | 非表示 | 親プロセスID |
| `processpath` | プロセスパス | `string` | 非表示 | 実行ファイルのパス |
| `pprocess` | 親プロセス | `string` | 非表示 | 親プロセス名 |
| `pprocesspath` | 親プロセスパス | `string` | 非表示 | 親プロセスのパス |
| `group` | グループ | `string` | 非表示 | グループ名 |
| `groupdomain` | グループドメイン | `string` | 非表示 | グループのドメイン |
| `groupsecurityid` | グループSID | `string` | 非表示 | WindowsグループSID |
| `member` | メンバー | `string` | 非表示 | グループメンバー名 |
| `memberdomain` | メンバードメイン | `string` | 非表示 | グループメンバーのドメイン |
| `membersecurityid` | メンバーSID | `string` | 非表示 | グループメンバーSID |
| `srcipv4` | 送信元IPv4 | `string` | 表示 | 送信元IPv4アドレス |
| `srcipv6` | 送信元IPv6 | `string` | 表示 | 送信元IPv6アドレス |
| `srcport` | 送信元ポート | `integer` | 非表示 | 送信元ポート番号 |
| `dstipv4` | 宛先IPv4 | `string` | 非表示 | 宛先IPv4アドレス |
| `dstipv6` | 宛先IPv6 | `string` | 非表示 | 宛先IPv6アドレス |
| `dstport` | 宛先ポート | `integer` | 非表示 | 宛先ポート番号 |
| `sessionid` | セッションID | `string` | 非表示 | セッション識別子 |

### 6.6 参考例: `unknown`

ログ送信元が `class=unknown` として送る場合の参考例である。LogSeekerが `unknown` を自動補完する意味ではない。クラス固有のKEY変換や補完は行わない。受信payloadは全KEY:VALUEを無改変で保持するが、表示・検索・集計・解析等の機能対象はTaxonomy KEYに一致した受信フィールドだけとする。Taxonomy外KEYは保存するだけで利用しない。

| KEY | 表示名 | 型 | 初期表示 | 用途 |
| --- | --- | --- | --- | --- |
| `class` | クラス | `string` | 表示 | ログやイベントの種類・ログソースを識別するクラス名。ログ送信元が設定したVALUEをそのまま使用する。 |
| `eventtime` | イベント時刻 | `string` | 表示 | イベント発生時刻 |
| `description` | メッセージ | `string` | 表示 | 原文またはイベント説明 |
| `hostname` | ホスト名 | `string` | 表示 | 方向が不明なホスト名 |
| `category` | カテゴリ | `string` | 表示 | イベントの分類カテゴリ |
| `action` | アクション | `string` | 表示 | イベントで発生/実行された動作 |
| `result` | 結果 | `string` | 表示 | success/failure等の最終結果 |
| `severity` | 重大度 | `string` | 表示 | イベント重大度 |

## 7. 現行EventsフィールドとTaxonomy KEYの参考対応
この表は、現在のLogSeeker Events出力と、今後ログ送信元が採用すると分かりやすいTaxonomy KEYの**参考対応**である。

**LogSeekerが受信後に左列のKEYを右列へ自動変換する仕様ではない。** 現行実装の移行方法は、既存DB・API・画面・本番データを調査して別途決定する。

| 現行フィールド | Taxonomy KEY候補 | 方針 |
|---|---|---|
| `id` | `—` | LogSeeker内部イベントID。Taxonomy KEYではない。 |
| `source` | `—` | ログソース識別用のLogSeeker管理メタデータ。 |
| `source_name` | `—` | ログソース表示名のLogSeeker管理メタデータ。 |
| `source_type` | `class` | 現行実装上の旧Class列。新規送信JSONではTaxonomy KEY `class` を使用する。LogSeeker受信後に `source_type` と `class` を相互変換する仕様ではなく、既存DB/APIからの移行は影響調査後に決定する。 |
| `received_at` | `—` | LogSeeker管理メタデータ。受信payload外で保持し、Taxonomy受信KEYへ変換しない。 |
| `event_time` | `eventtime` | 新規送信設定では `eventtime` を推奨する。既存値を受信後に改名しない。 |
| `event_category` | `category` | 新規送信設定での推奨候補。 |
| `event_action` | `action` | 新規送信設定での推奨候補。 |
| `event_result` | `result` | 新規送信設定での推奨候補。 |
| `event_severity` | `severity` | 新規送信設定での推奨候補。 |
| `device_name` | `devicename` / `hostname` | 意味に応じてログ送信元側で選択する。 |
| `source_ip` | `srcipv4` / `srcipv6` | 新規送信設定ではIPバージョンに応じたKEYを推奨する。 |
| `source_country` | `srccountry` / `srccountrycode` | 新規送信設定で国名または国コードをpayloadに含める場合の候補。LogSeekerのGeoIP解析結果は受信KEYへ書き戻さず、別の派生メタデータとして扱う。 |
| `source_asn` | `srcasn` | 新規送信設定でASNをpayloadに含める場合の候補。GeoIP解析結果を `srcasn` へ書き戻さない。 |
| `source_as_org` | `srcasorg` | 新規送信設定でAS組織名をpayloadに含める場合の候補。GeoIP解析結果を `srcasorg` へ書き戻さない。 |
| `actor_user` | `username` / `accountname` | イベント意味に応じてログ送信元側で選択する。 |
| `url_domain` | `domain` / `virtualdomain` / `virtualhost` 等 | 意味に応じてログ送信元側で選択する。LogSeekerは受信後に読み替えない。 |
| `url_path` | `uri` | 新規送信設定での推奨候補。 |
| `url_query` | `query` | 新規送信設定での推奨候補。 |
| `http_method` | `httpmethod` | 新規送信設定での推奨候補。 |
| `http_status_code` | `statuscode` | 新規送信設定での推奨候補。 |
| `service_name` | `service` | 意味に応じてログ送信元側で選択する。 |
| `message` | `description` | 新規送信設定での推奨候補。 |

## 8. 受信KEYの扱い
### 8.1 payloadはすべて無改変で保存する

受信JSONが次の場合:

```json
{
  "domain": "example.com",
  "virtualhost": "site-a",
  "vhost": "legacy-site",
  "host": "host.example.net"
}
```

LogSeekerは4つのKEY:VALUEをpayload内にそのまま保存する。KEYの削除・改名・コピー・統合は行わない。

`domain` / `vhost` / `virtualhost` / `host` はすべてTaxonomy KEYなので、受信JSONに存在する各KEY:VALUEを独立した受信フィールドとして表示・検索・集計等に利用できる。

```text
domain       → 受信フィールド。表示・検索・集計等に利用できる
vhost        → 受信フィールド。表示・検索・集計等に利用できる
virtualhost  → 受信フィールド。表示・検索・集計等に利用できる
host         → 受信フィールド。表示・検索・集計等に利用できる
```

同じイベントに複数存在しても、それぞれ別のKEY:VALUEとして保持し、相互変換しない。

### 8.2 VALUEがないフィールドは補完しない

```json
{
  "domain": "example.com"
}
```

この場合、受信フィールドとして利用できるのは実際に存在する `domain` だけである。`vhost` / `virtualhost` / `virtualdomain` / `host` / `hostname` 等をLogSeekerが生成・補完してはならない。

### 8.3 関連フィールドの優先順位はTaxonomy KEYだけで構成する

Dashboard等で「ドメイン／ホスト」を横断表示する場合は、Taxonomyに定義された関連KEYだけを候補にできる。Taxonomy外KEYを表示・集計優先順位へ含めてはならない。

初期優先順位は次を基準とする。

```text
domain
  > vhost
  > virtualhost
  > virtualdomain
  > host
  > hostname
```

優先順位を設定しても、受信payload、保存済みKEY名、VALUEは変更しない。詳細は `docs/normalize-mapping.md` を参照する。

## 9. 変更管理
- タクソノミーKEYの追加・削除・意味変更は `docs/taxonomy.md` を先に更新する。
- 標準KEY名変更はEvents表示設定・Dashboard集計設定・検索条件・ルール・相関・DBへの影響を確認してから行う。
- LogSeeker管理者／LogSeeker利用者が画面から任意のタクソノミーKEYを新規作成する方式にはしない。
- 未使用KEYを一覧に保持することと、DBに未使用構造を残置することは別。DBの不要テーブル／カラム／インデックスは依存関係を調査したうえで削除する。
