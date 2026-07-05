export function Placeholder({ title }: { title: string }) {
  return (
    <div className="card">
      <div className="empty">
        <p className="empty-title">{title}</p>
        <p className="empty-subtitle text-secondary">
          この画面はまだ未実装です（メニュー構成を最終形に合わせて先行表示しています）。
        </p>
      </div>
    </div>
  );
}
