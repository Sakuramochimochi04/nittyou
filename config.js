// ===== 設定ファイル =====
// Supabase の「Project Settings → API（または API Keys）」に出ている値を貼ってください。
// 2つとも空のままだと「お試しモード」になり、データはそのブラウザの中だけに保存されます。
// ここに貼るキーは公開用のキー（anon / publishable）です。service_role / secret キーは絶対に貼らないでください。
window.CHOSEI_CONFIG = {
  appName: 'みんなの日程調整',
  supabaseUrl: '',   // 例: 'https://abcdefghijkl.supabase.co'
  supabaseKey: ''    // 例: 'sb_publishable_xxxx' または 'eyJhbGciOi...'（anon key）
};
