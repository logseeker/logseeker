import { useEffect, useState } from "react";
import { api } from "./api";
import type { AuthStatus, EventsColumnCandidate } from "./types";

// Events一覧の「種別(Class)を1つに絞った時だけ」出せる追加列（受信payloadの生キー）の設定。
// 保存先はchangelogの既読状態と同じ方式：ログイン中はDB（user_settings、複数端末で共有）、
// 未ログイン（認証OFFのデモ運用時）はユーザーが定まらないためlocalStorageにフォールバックする。
const storageKey = (sourceType: string) => `logseeker_events_columns:${sourceType}`;

export function useEventsColumns(auth: AuthStatus | null, sourceType: string) {
  const [candidates, setCandidates] = useState<EventsColumnCandidate[]>([]);
  const [columns, setColumnsState] = useState<string[]>([]);
  const [loaded, setLoaded] = useState(false);
  const loggedIn = !!auth?.user;

  useEffect(() => {
    if (!sourceType) { setCandidates([]); return; }
    api.eventsColumnCandidates(sourceType).then((r) => setCandidates(r.keys)).catch(() => setCandidates([]));
  }, [sourceType]);

  useEffect(() => {
    if (!sourceType) { setColumnsState([]); setLoaded(true); return; }
    setLoaded(false);
    if (loggedIn) {
      api.getEventsColumns(sourceType)
        .then((r) => setColumnsState(r.columns ?? []))
        .catch(() => setColumnsState([]))
        .finally(() => setLoaded(true));
    } else {
      try {
        const raw = localStorage.getItem(storageKey(sourceType));
        setColumnsState(raw ? (JSON.parse(raw) as string[]) : []);
      } catch { setColumnsState([]); }
      setLoaded(true);
    }
  }, [loggedIn, sourceType]);

  const setColumns = (cols: string[]) => {
    if (!sourceType) return;
    setColumnsState(cols);
    if (loggedIn) {
      api.setEventsColumns(sourceType, cols).catch(() => {});
    } else {
      localStorage.setItem(storageKey(sourceType), JSON.stringify(cols));
    }
  };

  return { candidates, columns, setColumns, loaded };
}
