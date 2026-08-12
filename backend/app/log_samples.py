"""送信側（ログ元）の設定サンプル。

LogSeeker は受信したJSONのキー名が docs/taxonomy.md のTaxonomy KEYと
（大文字小文字を無視して）一致したものだけを表示・検索・集計に使う（設計書v12 §4.1.1, §15）。
したがって「送信側でTaxonomy KEYそのままの名前で出す」のが最短かつ唯一の正攻法で、
受信側でのキー読み替え（正規化）は本来不要になる。

ここに置いたサンプルはマッピング画面から参照できる。ホスト名・IP・ドメインは
すべてプレースホルダ（example.com / 192.0.2.10 等）で、実環境の値は書かない。

※ 使用するキーは必ず taxonomy_master.ALL_KEYS に実在するものだけにすること。
   起動時に検証しているので、非Taxonomyのキーを書くと RuntimeError で気付ける。
"""
from .taxonomy_master import is_taxonomy_key

# 送信先のプレースホルダ。実環境の値は絶対に書かない（公開リポジトリのため）。
HOST = "logseeker.example.com"
PORT = 516

SAMPLES: list[dict] = [
    # ------------------------------------------------------------------ Web
    {
        "id": "litespeed",
        "title": "LiteSpeed / OpenLiteSpeed",
        "target": "Webアクセスログ",
        "file": "/usr/local/lsws/conf/vhosts/<vhost>/<vhost>.conf",
        "lang": "apache",
        "note": "logFormat 全体を引用符で囲まない。囲むとその引用符ごと出力され、行頭が { でなくなる。",
        "keys": ["class", "eventtime", "vhost", "client", "username", "request",
                 "httpmethod", "uri", "status", "size", "referer", "user_agent"],
        "body": r"""accesslog $VH_ROOT/<vhost>/log/access.log {
  useServer               0
  rollingSize             10M
  keepDays                30
  # 1行=1JSON。行頭が { になるよう、値全体を " で囲まない。
  logFormat               { "class":"web_access", "eventtime":"%{%Y-%m-%dT%H:%M:%S%z}t", "vhost":"%v", "client":"%h", "username":"%u", "request":"%r", "httpmethod":"%m", "uri":"%U", "status":"%>s", "size":"%b", "referer":"%{Referer}i", "user_agent":"%{User-agent}i" }
}""",
    },
    {
        "id": "apache",
        "title": "Apache HTTP Server",
        "target": "Webアクセスログ",
        "file": "/etc/httpd/conf.d/logseeker.conf",
        "lang": "apache",
        "note": "%B はレスポンス本文のバイト数（0のとき %b は '-' になるため %B を使う）。",
        "keys": ["class", "eventtime", "vhost", "client", "username", "request",
                 "httpmethod", "uri", "status", "size", "referer", "user_agent"],
        "body": r"""LogFormat "{ \"class\":\"web_access\", \"eventtime\":\"%{%Y-%m-%dT%H:%M:%S%z}t\", \"vhost\":\"%v\", \"client\":\"%a\", \"username\":\"%u\", \"request\":\"%r\", \"httpmethod\":\"%m\", \"uri\":\"%U\", \"status\":\"%>s\", \"size\":\"%B\", \"referer\":\"%{Referer}i\", \"user_agent\":\"%{User-Agent}i\" }" logseeker_json

CustomLog "/var/log/httpd/access_json.log" logseeker_json""",
    },
    {
        "id": "nginx",
        "title": "nginx",
        "target": "Webアクセスログ",
        "file": "/etc/nginx/conf.d/logseeker.conf",
        "lang": "nginx",
        "note": "escape=json を付けないと、UAやURLに \" が含まれたときJSONが壊れる。",
        "keys": ["class", "eventtime", "vhost", "client", "username", "request",
                 "httpmethod", "uri", "status", "size", "referer", "user_agent"],
        "body": r"""log_format logseeker_json escape=json
  '{"class":"web_access",'
  '"eventtime":"$time_iso8601",'
  '"vhost":"$host",'
  '"client":"$remote_addr",'
  '"username":"$remote_user",'
  '"request":"$request",'
  '"httpmethod":"$request_method",'
  '"uri":"$uri",'
  '"status":"$status",'
  '"size":"$body_bytes_sent",'
  '"referer":"$http_referer",'
  '"user_agent":"$http_user_agent"}';

access_log /var/log/nginx/access_json.log logseeker_json;""",
    },
    # ---------------------------------------------------------------- 転送
    {
        "id": "nxlog_web",
        "title": "NXLog（Linux）― Webログの転送",
        "target": "上のJSONログをLogSeekerへ送る",
        "file": "/etc/nxlog/nxlog.d/web.conf",
        "lang": "apache",
        "note": "JSONでない行を drop() で捨てると、ログ形式が戻ったとき無言で欠測する。"
                "捨てずに message として送っておけば画面で異常に気付ける。",
        "keys": ["class", "source", "message", "eventtime"],
        "body": r"""<Extension _json>
    Module      xm_json
</Extension>

<Input in_web_access>
    Module      im_file
    File        "/var/log/nginx/access_json.log"
    <Exec>
        if $raw_event =~ /^\{/ {
            parse_json();
            $source = 'web01';
            $EventTime = parsedate($eventtime);
        } else {
            # 形式が戻った等でJSONでない行。捨てずにそのまま送り、画面で気付けるようにする。
            $class   = 'web_access';
            $source  = 'web01';
            $message = $raw_event;
        }
    </Exec>
</Input>

<Output out_logseeker>
    Module      om_tcp
    Host        logseeker.example.com
    Port        516
    OutputType  LineBased
    Exec        to_json();
</Output>

<Route r_web>
    Path        in_web_access => out_logseeker
</Route>""",
    },
    {
        "id": "nxlog_windows",
        "title": "NXLog（Windows）― イベントログ",
        "target": "Windowsイベントログ",
        "file": "C:\\Program Files\\nxlog\\conf\\nxlog.conf",
        "lang": "apache",
        "note": "im_msvistalog が出す Channel・Category 等はTaxonomy KEYではないキーも含むが、"
                "payloadには無改変で保存され、表示・検索には使われないだけなので消す必要はない。",
        "keys": ["class", "source", "eventid", "hostname", "severity", "message",
                 "accountname", "targetusername"],
        "body": r"""<Extension _json>
    Module      xm_json
</Extension>

<Input in_eventlog>
    Module      im_msvistalog
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Security">*</Select>
                <Select Path="System">*</Select>
                <Select Path="Application">*</Select>
            </Query>
        </QueryList>
    </QueryXML>
    <Exec>
        # class がクラス分けの唯一の根拠。これが無いと画面上 unknown になる。
        $class  = 'windows_event';
        $source = hostname_fqdn();
    </Exec>
</Input>

<Output out_logseeker>
    Module      om_tcp
    Host        logseeker.example.com
    Port        516
    OutputType  LineBased
    Exec        to_json();
</Output>

<Route r_evt>
    Path        in_eventlog => out_logseeker
</Route>""",
    },
    {
        "id": "nxlog_linux",
        "title": "NXLog（Linux）― syslog / auditd",
        "target": "/var/log/messages・/var/log/secure・auditd",
        "file": "/etc/nxlog/nxlog.d/local.conf",
        "lang": "apache",
        "note": "auditd は本文が key=value なので、送信側でTaxonomy KEYへ切り出しておくと検索できる。",
        "keys": ["class", "source", "hostname", "message", "severity",
                 "audit_type", "audit_res", "audit_acct", "sourceipaddress"],
        "body": r"""<Input in_messages>
    Module      im_file
    File        "/var/log/messages"
    <Exec>
        parse_syslog();
        $class    = 'linux';
        $source   = hostname_fqdn();
        $hostname = hostname_fqdn();
    </Exec>
</Input>

<Input in_secure>
    Module      im_file
    File        "/var/log/secure"
    <Exec>
        parse_syslog();
        $class    = 'linux';
        $source   = hostname_fqdn();
        $hostname = hostname_fqdn();
    </Exec>
</Input>

<Input in_audit>
    Module      im_file
    File        "/var/log/audit/audit.log"
    <Exec>
        $class   = 'audit';
        $source  = hostname_fqdn();
        $message = $raw_event;
        if $raw_event =~ /\btype=(\S+)/     { $audit_type = $1; }
        if $raw_event =~ /\bres=(\w+)/      { $audit_res  = $1; }
        if $raw_event =~ /\bacct="([^"]+)"/ { $audit_acct = $1; }
        if $raw_event =~ /\baddr=(\S+)/ {
            if $1 != '?' { $sourceipaddress = $1; }
        }
    </Exec>
</Input>

<Output out_logseeker>
    Module      om_tcp
    Host        logseeker.example.com
    Port        516
    OutputType  LineBased
    Exec        to_json();
</Output>

<Route r_local>
    Path        in_messages, in_secure, in_audit => out_logseeker
</Route>""",
    },
]


# サンプルが挙げているキーが本当にTaxonomy KEYか、起動時に検証する。
# （画面に「このキーを使え」と出す以上、実在しないキーを載せたら嘘になる）
for _s in SAMPLES:
    _bad = [k for k in _s["keys"] if not is_taxonomy_key(k)]
    if _bad:
        raise RuntimeError(f"log_samples: {_s['id']} に非Taxonomyのキーがある: {_bad}")
