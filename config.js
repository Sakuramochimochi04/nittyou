// ===== 設定ファイル =====
// Supabase の「Project Settings → API（または API Keys）」に出ている値を貼ってください。
// 2つとも空のままだと「お試しモード」になり、データはそのブラウザの中だけに保存されます。
// ここに貼るキーは公開用のキー（anon / publishable）です。service_role / secret キーは絶対に貼らないでください。
window.CHOSEI_CONFIG = {
  appName: "らくらく日程調整",
  supabaseUrl: "https://ommhpcawqkgaqwxegjvr.supabase.co", // 例: 'https://abcdefghijkl.supabase.co'
  supabaseKey: "sb_publishable_VoTmQaGMhewiyCvVSlYbfA_n1L9GZXS", // 例: 'sb_publishable_xxxx' または 'eyJhbGciOi...'（anon key）
};
