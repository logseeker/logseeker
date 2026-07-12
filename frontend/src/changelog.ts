import { useEffect, useState } from "react";
import { api } from "./api";
import type { AuthStatus, ReleaseItem } from "./types";

// 「閉じた」最新リリースのタグ名の保存先。
// ログイン中はDB（user_settings、複数端末で共有）、未ログイン（認証OFFのデモ運用時）は
// ユーザーが定まらないためlocalStorageにフォールバックする。
const DISMISSED_KEY = "logseeker_dismissed_release";

export function useChangelog(auth: AuthStatus | null) {
  const [releases, setReleases] = useState<ReleaseItem[]>([]);
  const [dismissed, setDismissed] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const loggedIn = !!auth?.user;

  useEffect(() => {
    api.changelog().then(setReleases).catch(() => {});
  }, []);

  useEffect(() => {
    setLoaded(false);
    if (loggedIn) {
      api.getDismissedRelease()
        .then((r) => setDismissed(r.last_dismissed_release))
        .catch(() => setDismissed(null))
        .finally(() => setLoaded(true));
    } else {
      setDismissed(localStorage.getItem(DISMISSED_KEY));
      setLoaded(true);
    }
  }, [loggedIn]);

  const latest = releases[0];
  // 未読＝最新リリースのタグ名が、保存済みの「閉じた」タグ名と異なる場合。
  // 1つ閉じたら、それより新しいリリースが出るまでは再表示しない。
  const unread = loaded && !!latest && latest.tag_name !== dismissed;

  const dismiss = () => {
    if (!latest) return;
    setDismissed(latest.tag_name);
    if (loggedIn) {
      api.setDismissedRelease(latest.tag_name).catch(() => {});
    } else {
      localStorage.setItem(DISMISSED_KEY, latest.tag_name);
    }
  };

  return { releases, latest, unread, dismiss, loaded };
}
