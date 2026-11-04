/* みんなの日程調整 — 暗号化リンク方式
 * 調整の中身はブラウザで AES-GCM 暗号化してから保存します。鍵は共有リンクの # 以降にだけあり、
 * サーバー（Supabase）には送られません。
 */
(() => {
  "use strict";

  const CFG = window.CHOSEI_CONFIG || {};
  const DEMO = !CFG.supabaseUrl || !CFG.supabaseKey;
  const APP_NAME = CFG.appName || "らくらく日程調整";
  const app = document.getElementById("app");
  const dock = document.getElementById("dock");
  document.getElementById("app-name").textContent = APP_NAME;
  document.title = APP_NAME;
  document.getElementById("demo-banner").hidden = !DEMO;

  const WD = ["日", "月", "火", "水", "木", "金", "土"];
  const SYM = { o: "◎", t: "△", x: "×" };
  const LABEL = { o: "行ける", t: "たぶん", x: "無理" };
  const PRIO = { x: 3, t: 2, o: 1 };

  /* ---------- 小さな道具 ---------- */
  const esc = (s) =>
    String(s ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
  const pad = (n) => String(n).padStart(2, "0");
  const hm = (t) => `${Math.floor(t / 60)}:${pad(t % 60)}`;
  const key = (t) => pad(Math.floor(t / 60)) + pad(t % 60);
  const toMin = (s) => {
    const [h, m] = String(s || "")
      .split(":")
      .map(Number);
    return isNaN(h) ? null : h * 60 + (m || 0);
  };
  const fromMin = (t) => `${pad(Math.floor(t / 60))}:${pad(t % 60)}`;
  function dParts(iso) {
    const [y, m, d] = iso.split("-").map(Number);
    return { y, m, d, w: new Date(y, m - 1, d).getDay() };
  }
  const dLabel = (iso) => {
    const p = dParts(iso);
    return `${p.m}/${p.d}(${WD[p.w]})`;
  };
  const slotsOf = (ev) => {
    const o = [];
    for (let t = ev.startMin; t < ev.endMin; t += ev.step) o.push(t);
    return o;
  };
  const LS = {
    get(k, d) {
      try {
        const v = localStorage.getItem(k);
        return v == null ? d : JSON.parse(v);
      } catch (e) {
        return d;
      }
    },
    set(k, v) {
      try {
        localStorage.setItem(k, JSON.stringify(v));
      } catch (e) {}
    },
  };
  function toast(m) {
    const t = document.getElementById("toast");
    t.textContent = m;
    t.hidden = false;
    clearTimeout(toast.t);
    toast.t = setTimeout(() => (t.hidden = true), 2400);
  }
  async function copyText(text, inputEl) {
    try {
      await navigator.clipboard.writeText(text);
      toast("コピーしました");
    } catch (e) {
      if (inputEl) {
        inputEl.focus();
        inputEl.select();
      }
      toast("選択された文字をコピーしてください");
    }
  }

  /* ---------- 暗号 ---------- */
  const enc = new TextEncoder(),
    dec = new TextDecoder();
  const b64u = {
    enc(buf) {
      const a = new Uint8Array(buf);
      let s = "";
      for (let i = 0; i < a.length; i += 0x8000)
        s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000));
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    },
    dec(str) {
      let s = str.replace(/-/g, "+").replace(/_/g, "/");
      while (s.length % 4) s += "=";
      const b = atob(s);
      const a = new Uint8Array(b.length);
      for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
      return a;
    },
  };
  const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
  const sha256 = async (str) =>
    b64u.enc(await crypto.subtle.digest("SHA-256", enc.encode(str)));
  const uuid = () =>
    crypto.randomUUID
      ? crypto.randomUUID()
      : ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, (c) =>
          (c ^ (rand(1)[0] & (15 >> (c / 4)))).toString(16),
        );
  async function importKey(k) {
    const raw = b64u.dec(k);
    if (raw.length !== 32) throw new Error("badkey");
    return crypto.subtle.importKey("raw", raw, "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]);
  }
  async function encryptObj(obj) {
    const iv = rand(12);
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(S.id) },
      S.key,
      enc.encode(JSON.stringify(obj)),
    );
    return { cipher: b64u.enc(ct), iv: b64u.enc(iv) };
  }
  async function decryptObj(row) {
    const pt = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: b64u.dec(row.iv),
        additionalData: enc.encode(S.id),
      },
      S.key,
      b64u.dec(row.cipher),
    );
    return JSON.parse(dec.decode(pt));
  }
  // パスワードは「調整ID＋鍵＋パスワード」から作った値にしてから送る（サーバーは元のパスワードも鍵も知らない）
  const verifier = (scope, pass, answerId = "") =>
    sha256(`chosei-v1|${S.id}|${S.keyB64}|${scope}|${answerId}|${pass}`);

  /* ---------- サーバー ---------- */
  async function rpc(fn, params) {
    if (DEMO) return demo.call(fn, params);
    const h = { "Content-Type": "application/json", apikey: CFG.supabaseKey };
    if (CFG.supabaseKey.startsWith("eyJ"))
      h.Authorization = "Bearer " + CFG.supabaseKey;
    let r;
    // 「https://xxx.supabase.co/rest/v1/」のように後ろまで貼られていても動くように整える
    const base = CFG.supabaseUrl
      .trim()
      .replace(/\/+$/, "")
      .replace(/\/rest\/v1$/, "")
      .replace(/\/+$/, "");
    try {
      r = await fetch(`${base}/rest/v1/rpc/${fn}`, {
        method: "POST",
        headers: h,
        body: JSON.stringify(params),
      });
    } catch (e) {
      const er = new Error("network");
      er.kind = "net";
      throw er;
    }
    const txt = await r.text();
    if (!r.ok) {
      const er = new Error(txt || "HTTP " + r.status);
      er.kind = "server";
      throw er;
    }
    return txt ? JSON.parse(txt) : null;
  }
  // お試しモード：Supabase と同じ関数をブラウザ内で真似する
  const demo = {
    load() {
      return LS.get("chosei.demoDB", { events: {}, answers: {} });
    },
    save(d) {
      LS.set("chosei.demoDB", d);
    },
    h(s) {
      return sha256("demo|" + s);
    },
    async call(fn, p) {
      await new Promise((r) => setTimeout(r, 150));
      const d = this.load(),
        now = new Date().toISOString();
      const ownerOk = async (id) =>
        !!d.events[id] && d.events[id].owner_hash === (await this.h(p.p_owner));
      switch (fn) {
        case "create_event":
          d.events[p.p_id] = {
            cipher: p.p_cipher,
            iv: p.p_iv,
            owner_hash: await this.h(p.p_owner),
            created_at: now,
            updated_at: now,
          };
          this.save(d);
          return null;
        case "get_event": {
          const e = d.events[p.p_id];
          return {
            event: e
              ? { cipher: e.cipher, iv: e.iv, updated_at: e.updated_at }
              : null,
            answers: Object.entries(d.answers)
              .filter(([, a]) => a.event_id === p.p_id)
              .map(([id, a]) => ({
                id,
                cipher: a.cipher,
                iv: a.iv,
                created_at: a.created_at,
                updated_at: a.updated_at,
              }))
              .sort((a, b) => (a.created_at < b.created_at ? -1 : 1)),
          };
        }
        case "check_owner":
          return ownerOk(p.p_id);
        case "update_event":
          if (!(await ownerOk(p.p_id))) return false;
          Object.assign(d.events[p.p_id], {
            cipher: p.p_cipher,
            iv: p.p_iv,
            updated_at: now,
          });
          this.save(d);
          return true;
        case "delete_event":
          if (!(await ownerOk(p.p_id))) return false;
          delete d.events[p.p_id];
          for (const [id, a] of Object.entries(d.answers))
            if (a.event_id === p.p_id) delete d.answers[id];
          this.save(d);
          return true;
        case "create_answer":
          if (!d.events[p.p_event]) throw new Error("event not found");
          d.answers[p.p_id] = {
            event_id: p.p_event,
            cipher: p.p_cipher,
            iv: p.p_iv,
            pass_hash: await this.h(p.p_pass),
            created_at: now,
            updated_at: now,
          };
          this.save(d);
          return null;
        case "check_answer":
          return (
            !!d.answers[p.p_id] &&
            d.answers[p.p_id].pass_hash === (await this.h(p.p_pass))
          );
        case "update_answer": {
          const a = d.answers[p.p_id];
          if (!a || a.pass_hash !== (await this.h(p.p_pass))) return false;
          Object.assign(a, { cipher: p.p_cipher, iv: p.p_iv, updated_at: now });
          this.save(d);
          return true;
        }
        case "delete_answer": {
          const a = d.answers[p.p_id];
          if (!a || a.pass_hash !== (await this.h(p.p_pass))) return false;
          delete d.answers[p.p_id];
          this.save(d);
          return true;
        }
        case "owner_delete_answer":
          if (!(await ownerOk(p.p_event))) return false;
          if (d.answers[p.p_answer]?.event_id !== p.p_event) return false;
          delete d.answers[p.p_answer];
          this.save(d);
          return true;
      }
      throw new Error("unknown fn");
    },
  };

  /* ---------- この端末に覚えておくもの ---------- */
  const myEvents = () => LS.get("chosei.events", []);
  function rememberEvent(role) {
    const list = myEvents().filter((e) => e.id !== S.id);
    const old = myEvents().find((e) => e.id === S.id);
    list.unshift({
      id: S.id,
      k: S.keyB64,
      title: S.ev.title,
      owner: role === "owner" || !!old?.owner,
      at: Date.now(),
    });
    LS.set("chosei.events", list.slice(0, 50));
  }
  const mine = () => LS.get("chosei.mine", {});
  function rememberAnswer(answerId, ver) {
    const m = mine();
    (m[S.id] ||= {})[answerId] = ver;
    LS.set("chosei.mine", m);
  }
  function forgetAnswer(answerId) {
    const m = mine();
    if (m[S.id]) {
      delete m[S.id][answerId];
      LS.set("chosei.mine", m);
    }
  }
  const myVerFor = (id) => S.session[id] || mine()[S.id]?.[id] || null;
  const presets = () => {
    const p = LS.get("chosei.presets", null) || {};
    p.weekly ||= {};
    p.patterns ||= [];
    return p;
  };
  const savePresets = (p) => LS.set("chosei.presets", p);

  /* ---------- 状態とルーティング ---------- */
  const S = {
    id: null,
    keyB64: null,
    key: null,
    ev: null,
    answers: [],
    sig: "",
    loading: false,
    err: null,
    owner: null,
    session: {},
    tab: "heat",
    sel: null,
    unlockFor: null,
    ownerOpen: false,
    pendingDel: null,
    form: null,
    draft: null,
    prTab: "weekly",
  };
  function route() {
    const p = new URLSearchParams(location.hash.slice(1));
    return { e: p.get("e"), k: p.get("k"), v: p.get("v") || "", a: p.get("a") };
  }
  function link(extra = {}) {
    const p = new URLSearchParams();
    if (S.id) {
      p.set("e", S.id);
      p.set("k", S.keyB64);
    }
    for (const [k, v] of Object.entries(extra)) if (v != null) p.set(k, v);
    return "#" + p.toString();
  }
  const shareUrl = () =>
    location.origin + location.pathname + `#e=${S.id}&k=${S.keyB64}`;
  function go(h) {
    if (location.hash === h) render();
    else location.hash = h;
  }

  window.addEventListener("hashchange", onRoute);
  onRoute();
  setInterval(() => {
    const r = route();
    if (r.e && S.ev && document.visibilityState === "visible" && !r.v)
      loadEvent(true);
  }, 20000);
  document.addEventListener("visibilitychange", () => {
    const r = route();
    if (document.visibilityState === "visible" && r.e && S.ev && !r.v)
      loadEvent(true);
  });

  async function onRoute() {
    const r = route();
    S.sel = null;
    S.unlockFor = S.nextUnlock || null;
    S.nextUnlock = null;
    S.pendingDel = null;
    S.form = null;
    if (r.v !== "answer") S.draft = null;
    window.scrollTo(0, 0);
    if (r.e && r.k && (r.e !== S.id || r.k !== S.keyB64)) {
      Object.assign(S, {
        id: r.e,
        keyB64: r.k,
        key: null,
        ev: null,
        answers: [],
        sig: "",
        err: null,
        owner: null,
        session: {},
        ownerOpen: false,
      });
      try {
        S.key = await importKey(r.k);
      } catch (e) {
        S.err = "key";
        render();
        return;
      }
      await loadEvent(false);
      return;
    }
    render();
  }

  async function loadEvent(silent) {
    if (!silent) {
      S.loading = true;
      render();
    }
    try {
      const res = await rpc("get_event", { p_id: S.id });
      if (!res || !res.event) {
        S.err = "notfound";
        S.loading = false;
        render();
        return;
      }
      const sig =
        res.event.updated_at +
        "|" +
        res.answers.map((a) => a.id + a.updated_at).join(",");
      if (silent && sig === S.sig) return;
      try {
        S.ev = await decryptObj(res.event);
      } catch (e) {
        S.err = "key";
        S.loading = false;
        render();
        return;
      }
      const out = [];
      for (const a of res.answers) {
        try {
          out.push({
            id: a.id,
            created_at: a.created_at,
            updated_at: a.updated_at,
            ...(await decryptObj(a)),
          });
        } catch (e) {}
      }
      S.answers = out;
      S.sig = sig;
      S.err = null;
      rememberEvent();
    } catch (e) {
      if (!silent) S.err = "net";
    }
    S.loading = false;
    const r = route();
    const typing =
      document.activeElement &&
      /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
    if (silent && (r.v || typing)) return;
    const y = window.scrollY;
    render();
    if (silent) window.scrollTo(0, y);
  }

  /* ---------- 描画の入口 ---------- */
  function render() {
    dock.innerHTML = "";
    const r = route();
    if (r.v === "presets") return renderPresets();
    if (r.v === "new") return renderForm(false);
    if (!r.e) return renderHome();
    if (S.err === "key")
      return msg(
        "リンクが正しくありません",
        "リンクの最後まで（#以降の鍵も含めて）コピーされているか確認してください。",
      );
    if (S.err === "notfound")
      return msg(
        "この調整は見つかりません",
        "削除されたか、リンクが間違っている可能性があります。",
      );
    if (S.err === "net" && !S.ev)
      return msg(
        "読み込めませんでした",
        "通信状態を確認して、ページを開き直してください。",
      );
    if (!S.ev) {
      app.innerHTML = `<p class="muted">読み込み中…</p>`;
      return;
    }
    if (r.v === "created") return renderCreated();
    if (r.v === "edit") return renderForm(true);
    if (r.v === "answer") return renderAnswer(r.a);
    renderEvent();
  }
  function msg(t, d) {
    app.innerHTML = `<div class="empty"><h2>${esc(t)}</h2><p class="muted small">${esc(d)}</p><a class="btn" href="#">トップに戻る</a></div>`;
  }

  /* ---------- トップ ---------- */
  function renderHome() {
    const list = myEvents();
    let h = `<div class="stack">
    <div class="hero">
      <h1>ユニット練習の日程、<br>空いている時間を塗ってそろえる</h1>
      <p class="muted">候補日を決めて共有すると、メンバーが日付ごとに ◎ △ × で行ける時間を塗れます。全員の重なりがひと目でわかります。</p>
      <div class="lock"><span aria-hidden="true">🔒</span><span><b>中身は暗号化して保存。</b>読めるのはリンクを知っているメンバーだけで、運営者にも見えません。</span></div>
      <a class="btn primary block" href="#v=new">新しい調整を作る</a>
    </div>`;
    if (list.length) {
      h +=
        `<section class="stack" style="gap:10px"><div class="eyebrow">この端末で開いた調整</div><div class="evlist">` +
        list
          .map(
            (e) =>
              `<div class="ev"><a href="#e=${esc(e.id)}&k=${esc(e.k)}"><div class="ev-title">${esc(e.title)}</div><div class="ev-meta">${e.owner ? "オーナー ・ " : ""}${new Date(e.at).getMonth() + 1}/${new Date(e.at).getDate()} に開いた</div></a><button class="linkbtn quiet" data-act="forget-ev" data-id="${esc(e.id)}" aria-label="一覧から消す">×</button></div>`,
          )
          .join("") +
        `</div><p class="hint">× はこの端末の一覧から消すだけで、調整そのものは消えません。</p></section>`;
    }
    h += `<section class="panel"><h2>いつもの予定を登録しておく</h2><p class="small muted">授業やバイトなど、曜日ごとの予定やよく使うパターンを登録すると、入力のときにワンタップで塗れます。</p><a class="btn" href="#v=presets">いつもの予定を編集</a></section></div>`;
    app.innerHTML = h;
  }

  /* ---------- 調整の作成・編集（オーナー） ---------- */
  function renderForm(isEdit) {
    if (isEdit && !S.owner) {
      go(link());
      return;
    }
    if (!S.form) {
      const now = new Date();
      S.form = isEdit
        ? {
            title: S.ev.title,
            memo: S.ev.memo || "",
            dates: [...S.ev.dates],
            startMin: S.ev.startMin,
            endMin: S.ev.endMin,
            step: S.ev.step,
            ym: [dParts(S.ev.dates[0]).y, dParts(S.ev.dates[0]).m - 1],
            p1: "",
            p2: "",
          }
        : {
            title: "",
            memo: "",
            dates: [],
            startMin: 10 * 60,
            endMin: 22 * 60,
            step: 30,
            ym: [now.getFullYear(), now.getMonth()],
            p1: "",
            p2: "",
          };
    }
    const F = S.form,
      [Y, M] = F.ym;
    const first = new Date(Y, M, 1).getDay(),
      days = new Date(Y, M + 1, 0).getDate();
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    let cal = WD.map(
      (w, i) =>
        `<button type="button" class="wd ${i === 0 ? "sun" : i === 6 ? "sat" : ""}" data-act="cal-wd" data-w="${i}" aria-label="${M + 1}月の${w}曜日をまとめて選ぶ">${w}</button>`,
    ).join("");
    for (let i = 0; i < first; i++) cal += `<span></span>`;
    for (let d = 1; d <= days; d++) {
      const iso = `${Y}-${pad(M + 1)}-${pad(d)}`,
        wd = new Date(Y, M, d).getDay();
      cal += `<button type="button" data-act="cal" data-iso="${iso}" class="${wd === 0 ? "sun" : wd === 6 ? "sat" : ""} ${new Date(Y, M, d) < today ? "past" : ""}" aria-pressed="${F.dates.includes(iso)}" aria-label="${M + 1}月${d}日">${d}</button>`;
    }
    const opts = (sel, from, to) => {
      let o = "";
      for (let t = from; t <= to; t += 30)
        o += `<option value="${t}" ${t === sel ? "selected" : ""}>${hm(t)}</option>`;
      return o;
    };
    app.innerHTML = `<form class="stack" id="evform" novalidate>
    <div><a class="linkbtn" href="${isEdit ? link() : "#"}">← 戻る</a></div>
    <h1>${isEdit ? "調整を編集" : "新しい調整を作る"}</h1>
    <div class="panel">
      <label class="f">タイトル<input type="text" id="f-title" maxlength="60" value="${esc(F.title)}" placeholder="例：Aユニット 12月練習"></label>
      <label class="f">メモ <span class="hint">場所・内容・締め切りなど（任意）</span><textarea id="f-memo" maxlength="400" placeholder="例：スタジオ候補は渋谷と代々木。12/1(月)までに入力してね">${esc(F.memo)}</textarea></label>
    </div>
    <div class="panel">
      <div class="cal-head"><button type="button" class="btn sm" data-act="month" data-d="-1" aria-label="前の月">‹</button><b>${Y}年 ${M + 1}月</b><button type="button" class="btn sm" data-act="month" data-d="1" aria-label="次の月">›</button></div>
      <p class="hint">日付をタップ、または指でなぞってまとめて選べます（選んだ日からなぞると解除）。曜日の文字をタップすると、その月のその曜日をまとめて選べます。</p>
      <div class="cal" id="cal">${cal}</div>
      <div class="chips" id="cal-chips">${F.dates.length ? F.dates.map((d) => `<span class="chip">${dLabel(d)}</span>`).join("") : '<span class="hint">まだ日付が選ばれていません</span>'}</div>
    </div>
    <div class="panel">
      <h2>入力してもらう時間帯</h2>
      <div class="row"><select id="f-start" aria-label="開始" style="flex:1 1 100px;width:auto">${opts(F.startMin, 5 * 60, 23 * 60)}</select><span>〜</span><select id="f-end" aria-label="終了" style="flex:1 1 100px;width:auto">${opts(F.endMin, 6 * 60, 24 * 60)}</select></div>
      <div class="f">区切り<span class="seg"><button type="button" data-act="step" data-v="30" aria-pressed="${F.step === 30}">30分</button><button type="button" data-act="step" data-v="60" aria-pressed="${F.step === 60}">1時間</button></span></div>
      ${isEdit ? '<p class="hint">時間帯や区切りを変えると、メンバーがすでに塗った時間の一部が表示されなくなることがあります。</p>' : ""}
    </div>
    ${
      isEdit
        ? ""
        : `<div class="panel">
      <h2>オーナー用パスワード</h2>
      <p class="small muted">日付の変更や削除に使います。忘れると誰も変更できなくなるので、メモしておいてください。</p>
      <label class="f">パスワード<input type="password" id="f-p1" autocomplete="new-password" minlength="4" value="${esc(F.p1)}"></label>
      <label class="f">もう一度<input type="password" id="f-p2" autocomplete="new-password" value="${esc(F.p2)}"></label>
    </div>`
    }
    <p class="status err" id="f-st" role="alert"></p>
    <button class="btn primary block" type="submit" id="f-save">${isEdit ? "変更を保存" : "作成してリンクを発行"}</button>
    ${
      isEdit
        ? S.pendingDel === "event"
          ? `<div class="confirm"><p><b>「${esc(S.ev.title)}」を削除しますか？</b><br><span class="small muted">メンバーの回答もすべて消え、元に戻せません。</span></p><div class="row"><button type="button" class="btn danger" data-act="del-event-yes">削除する</button><button type="button" class="btn" data-act="cancel-del">やめる</button></div></div>`
          : `<button type="button" class="linkbtn quiet" data-act="del-event" style="align-self:flex-start">この調整を削除</button>`
        : ""
    }
  </form>`;
    document.getElementById("evform").addEventListener("submit", (e) => {
      e.preventDefault();
      saveEventForm(isEdit);
    });
  }
  function syncForm() {
    const F = S.form;
    if (!F) return;
    const v = (id) => document.getElementById(id);
    F.title = v("f-title").value;
    F.memo = v("f-memo").value;
    F.startMin = +v("f-start").value;
    F.endMin = +v("f-end").value;
    if (v("f-p1")) {
      F.p1 = v("f-p1").value;
      F.p2 = v("f-p2").value;
    }
  }
  async function saveEventForm(isEdit) {
    syncForm();
    const F = S.form,
      st = document.getElementById("f-st");
    const title = F.title.trim();
    if (!title) return (st.textContent = "タイトルを入力してください。");
    if (!F.dates.length)
      return (st.textContent = "候補日を1日以上選んでください。");
    if (F.endMin <= F.startMin)
      return (st.textContent = "終了時刻は開始時刻より後にしてください。");
    if ((F.endMin - F.startMin) % F.step)
      return (st.textContent =
        "1時間区切りのときは、開始と終了の差を1時間単位にしてください。");
    if (!isEdit) {
      if (F.p1.length < 4)
        return (st.textContent =
          "オーナー用パスワードは4文字以上にしてください。");
      if (F.p1 !== F.p2) return (st.textContent = "パスワードが一致しません。");
    }
    const btn = document.getElementById("f-save");
    btn.disabled = true;
    st.textContent = "";
    const body = {
      title,
      memo: F.memo.trim(),
      dates: [...F.dates].sort(),
      startMin: F.startMin,
      endMin: F.endMin,
      step: F.step,
    };
    try {
      if (isEdit) {
        const c = await encryptObj({ ...S.ev, ...body });
        const ok = await rpc("update_event", {
          p_id: S.id,
          p_owner: S.owner,
          p_cipher: c.cipher,
          p_iv: c.iv,
        });
        if (!ok) {
          btn.disabled = false;
          S.owner = null;
          return (st.textContent =
            "オーナー用パスワードが確認できませんでした。もう一度ログインしてください。");
        }
        S.ev = { ...S.ev, ...body };
        S.sig = "";
        rememberEvent("owner");
        toast("保存しました");
        go(link());
      } else {
        const keyRaw = rand(32);
        S.id = b64u.enc(rand(16));
        S.keyB64 = b64u.enc(keyRaw);
        S.key = await importKey(S.keyB64);
        S.answers = [];
        S.session = {};
        S.err = null;
        const c = await encryptObj({ ...body, createdAt: Date.now() });
        const ver = await verifier("owner", F.p1);
        await rpc("create_event", {
          p_id: S.id,
          p_cipher: c.cipher,
          p_iv: c.iv,
          p_owner: ver,
        });
        S.ev = { ...body };
        S.owner = ver;
        S.sig = "";
        rememberEvent("owner");
        go(link({ v: "created" }));
      }
    } catch (e) {
      btn.disabled = false;
      st.textContent =
        e.kind === "net"
          ? "通信できませんでした。電波の良いところでもう一度お試しください。"
          : "保存できませんでした。時間をおいてもう一度お試しください。";
    }
  }

  /* ---------- 作成完了：リンクを渡す ---------- */
  function renderCreated() {
    app.innerHTML = `<div class="stack">
    <div><div class="eyebrow">作成しました</div><h1>${esc(S.ev.title)}</h1></div>
    <div class="panel">
      <h2>メンバーに送るリンク</h2>
      <div class="linkbox"><input type="text" id="share" readonly value="${esc(shareUrl())}" aria-label="共有リンク"><button class="btn primary" data-act="copy-link">コピー</button></div>
      <div class="warn"><b>このリンクが鍵です。</b>なくすと、オーナーも含めて誰も開けなくなります（運営者も復元できません）。LINEのノートやメモアプリに保存しておいてください。</div>
      <button class="btn" data-act="copy-invite">案内文つきでコピー</button>
    </div>
    <a class="btn block" href="${link()}">調整を開く</a>
  </div>`;
  }
  const inviteText = () =>
    `【${S.ev.title}】日程調整\n${S.ev.memo ? S.ev.memo + "\n" : ""}候補日：${S.ev.dates.map(dLabel).join("、")}\n${hm(S.ev.startMin)}〜${hm(S.ev.endMin)}で行ける時間を ◎△× で入力してください！\n${shareUrl()}`;

  /* ---------- 集計 ---------- */
  function counts(date, t) {
    let o = 0,
      tt = 0,
      x = 0;
    const k = key(t);
    for (const a of S.answers) {
      const m = a.marks?.[date]?.[k];
      if (m === "o") o++;
      else if (m === "t") tt++;
      else if (m === "x") x++;
    }
    return { o, t: tt, x };
  }
  function rangesOf(dayMarks, ev) {
    const out = [];
    let cur = null;
    for (const t of slotsOf(ev)) {
      const m = dayMarks?.[key(t)] || "";
      if (cur && cur.m === m) cur.end = t + ev.step;
      else {
        if (cur && cur.m) out.push(cur);
        cur = { m, start: t, end: t + ev.step };
      }
    }
    if (cur && cur.m) out.push(cur);
    return out;
  }
  const heatBg = (r) =>
    r <= 0
      ? "var(--bg)"
      : `color-mix(in srgb, var(--hot) ${Math.round(14 + r * 76)}%, var(--surface))`;

  /* ---------- 日付ごとの表（メンバー × 時間） ---------- */
  function renderTimeline(ev, slots) {
    const N = S.answers.length;
    let h = `<div class="legend"><span><span class="tl-key o">◎</span> 行ける</span><span><span class="tl-key t">△</span> たぶん</span><span><span class="tl-key x">×</span> 無理</span><span><span class="tl-key"></span> 未入力</span></div>`;
    if (!N) return h + `<p class="muted small">まだ誰も入力していません。</p>`;
    const perHour = 60 / ev.step;
    for (const d of ev.dates) {
      // 時刻の目盛り：枠の境目（左端）に書く。毎時ちょうどのみ。
      let head = "";
      for (const t of slots) {
        const onHour = t % 60 === 0;
        head += `<th class="tl-h ${onHour ? "hr" : ""}">${onHour ? `<span>${Math.floor(t / 60)}</span>` : ""}</th>`;
      }
      const endLabel =
        ev.endMin % 60 === 0
          ? `<span class="end">${ev.endMin / 60}</span>`
          : "";
      let rows = "";
      for (const a of S.answers) {
        rows += `<tr><th class="tl-name" scope="row">${esc(a.name)}</th>`;
        for (const t of slots) {
          const m = a.marks?.[d]?.[key(t)] || "";
          rows += `<td class="tl-c ${m} ${t % 60 === 0 ? "hr" : ""}" title="${esc(a.name)} ${hm(t)}〜${hm(t + ev.step)} ${m ? LABEL[m] : "未入力"}">${m ? SYM[m] : ""}</td>`;
        }
        rows += `</tr>`;
      }
      // いちばん下に ◎ の人数
      let sum = `<tr class="tl-sum"><th class="tl-name" scope="row">◎の人数</th>`;
      for (const t of slots) {
        const c = counts(d, t);
        sum += `<td class="tl-c ${t % 60 === 0 ? "hr" : ""} ${c.o === N ? "all" : ""}">${c.o || ""}</td>`;
      }
      sum += `</tr>`;
      const notes = S.answers
        .filter((a) => a.notes?.[d])
        .map(
          (a) =>
            `<div class="note"><b>${esc(a.name)}</b>：${esc(a.notes[d])}</div>`,
        )
        .join("");
      h += `<section class="tl-day"><h2>${dLabel(d)}</h2>
      <div class="gridbox"><table class="tl" style="--cw:${perHour === 1 ? 34 : 22}px"><thead><tr><th class="tl-name"></th>${head}<th class="tl-endh">${endLabel}</th></tr></thead><tbody>${rows}${sum}</tbody></table></div>
      ${notes ? `<div class="stack" style="gap:2px">${notes}</div>` : ""}</section>`;
    }
    return (
      h +
      `<p class="hint">表が横に長いときは、表の中を左右にスクロールできます。</p>`
    );
  }

  /* ---------- 調整のページ（一覧） ---------- */
  function renderEvent() {
    const ev = S.ev,
      N = S.answers.length,
      slots = slotsOf(ev);
    const mineIds = Object.keys(mine()[S.id] || {}).concat(
      Object.keys(S.session),
    );
    const myAns = S.answers.find((a) => mineIds.includes(a.id));

    let h = `<div class="stack">
    <div class="stack" style="gap:6px"><h1>${esc(ev.title)}</h1>
      <p class="small muted">${ev.dates.length}日 ・ ${hm(ev.startMin)}〜${hm(ev.endMin)} ・ ${ev.step === 60 ? "1時間" : "30分"}区切り</p>
      ${ev.memo ? `<div class="memo" style="background:var(--surface);border:1px solid var(--line)">${esc(ev.memo)}</div>` : ""}</div>
    ${
      myAns
        ? `<a class="btn primary block" href="${link({ v: "answer", a: myAns.id })}">自分の予定を編集（${esc(myAns.name)}）</a>`
        : `<a class="btn primary block" href="${link({ v: "answer" })}">◎△× で行ける時間を入力する</a>`
    }`;

    if (N) {
      let maxO = 0;
      for (const d of ev.dates)
        for (const t of slots) maxO = Math.max(maxO, counts(d, t).o);
      if (maxO > 0) {
        const lines = [];
        for (const d of ev.dates) {
          let run = null;
          for (const t of [...slots, null]) {
            const ok = t !== null && counts(d, t).o === maxO;
            if (ok) {
              if (!run) run = { s: t, e: t + ev.step };
              else run.e = t + ev.step;
            } else if (run) {
              lines.push(
                `<div class="best-row"><span>${dLabel(d)}</span><b>${hm(run.s)}〜${hm(run.e)}</b></div>`,
              );
              run = null;
            }
          }
        }
        h += `<section class="panel" style="gap:6px"><div class="eyebrow">${maxO === N ? `全員（${N}人）が ◎ の時間` : `◎ がいちばん多い時間（${maxO}/${N}人）`}</div>${lines.slice(0, 8).join("")}${lines.length > 8 ? `<p class="hint">ほか ${lines.length - 8} 件</p>` : ""}</section>`;
      }
    }

    h += `<div class="tabs" role="tablist"><button role="tab" data-act="tab" data-v="heat" aria-selected="${S.tab === "heat"}">重なり</button><button role="tab" data-act="tab" data-v="line" aria-selected="${S.tab === "line"}">日付ごとの表</button><button role="tab" data-act="tab" data-v="list" aria-selected="${S.tab === "list"}">メンバー別</button></div>`;

    if (S.tab === "heat") {
      h += `<div class="legend"><span>◎の人数</span><span class="ramp">${[0, 0.25, 0.5, 0.75, 1].map((r) => `<i style="background:${heatBg(r)}"></i>`).join("")}</span><span>少 → 多</span><span>黒枠＝全員◎</span></div>`;
      h += `<div class="gridbox"><table class="heat"><thead><tr><th class="t" style="height:auto"></th>${ev.dates
        .map((d) => {
          const p = dParts(d);
          return `<th><span class="d">${p.m}/${p.d}</span>${WD[p.w]}</th>`;
        })
        .join("")}</tr></thead><tbody>`;
      for (const t of slots) {
        h += `<tr><th class="t"><span>${hm(t)}</span></th>`;
        for (const d of ev.dates) {
          const c = counts(d, t),
            r = N ? (c.o + c.t * 0.4) / N : 0,
            sel = S.sel && S.sel.d === d && S.sel.t === t;
          h += `<td><button class="hc ${N && c.o === N ? "full" : ""}" data-act="cell" data-d="${d}" data-t="${t}" aria-pressed="${!!sel}" style="background:${heatBg(r)}" aria-label="${dLabel(d)} ${hm(t)}〜${hm(t + ev.step)} ◎${c.o}人 △${c.t}人">${c.o ? "◎" + c.o : c.t ? "△" + c.t : ""}</button></td>`;
        }
        h += `</tr>`;
      }
      h += `<tr class="endrow"><th class="t"><span>${hm(ev.endMin)}</span></th>${ev.dates.map(() => "<td></td>").join("")}</tr></tbody></table></div>`;
      if (S.sel) {
        const { d, t } = S.sel,
          k = key(t),
          g = { o: [], t: [], x: [], n: [] };
        for (const a of S.answers) {
          const m = a.marks?.[d]?.[k];
          (g[m] || g.n).push(a.name);
        }
        h += `<section class="panel"><h2>${dLabel(d)} ${hm(t)}〜${hm(t + ev.step)}</h2><div class="detail">
        <span class="k" style="color:var(--maru)">◎</span><span>${g.o.map(esc).join("、") || "—"}</span>
        <span class="k" style="color:var(--sankaku)">△</span><span>${g.t.map(esc).join("、") || "—"}</span>
        <span class="k" style="color:var(--batsu)">×</span><span>${g.x.map(esc).join("、") || "—"}</span>
        <span class="k muted">未</span><span class="muted">${g.n.map(esc).join("、") || "—"}</span></div></section>`;
      } else if (N)
        h += `<p class="hint">マスをタップすると、その時間に誰が行けるか表示されます。</p>`;
    } else if (S.tab === "line") {
      h += renderTimeline(ev, slots);
    } else {
      h += `<section class="panel">`;
      if (!N) h += `<p class="muted small">まだ誰も入力していません。</p>`;
      for (const a of S.answers) {
        const isMine = mineIds.includes(a.id);
        h += `<div class="mem"><div class="mem-head"><span class="mem-name">${esc(a.name)}</span><span class="row" style="gap:12px">
        ${S.owner ? (S.pendingDel === a.id ? `<button class="linkbtn red" data-act="owner-del-ans-yes" data-id="${a.id}">本当に消す</button><button class="linkbtn quiet" data-act="cancel-del">やめる</button>` : `<button class="linkbtn quiet" data-act="owner-del-ans" data-id="${a.id}">削除</button>`) : ""}
        <button class="linkbtn" data-act="${isMine ? "open-mine" : "unlock"}" data-id="${a.id}">編集</button></span></div>`;
        if (S.unlockFor === a.id) {
          h += `<div class="unlock"><label class="f">${esc(a.name)} さんのパスワード<input type="password" id="u-pass" autocomplete="current-password"></label>
          <label class="check"><input type="checkbox" id="u-rem" checked>この端末では次から入力しない</label>
          <p class="status err" id="u-st" role="alert"></p>
          <div class="row"><button class="btn primary sm" data-act="unlock-go" data-id="${a.id}">開く</button><button class="btn sm" data-act="unlock-cancel">やめる</button></div></div>`;
        }
        for (const d of ev.dates) {
          const rs = rangesOf(a.marks?.[d], ev),
            note = a.notes?.[d];
          h += `<div class="mem-day"><span class="dl">${dLabel(d)}</span><div style="min-width:0;display:flex;flex-direction:column;gap:3px"><div class="ranges">${rs.length ? rs.map((r) => `<span class="rg ${r.m}">${SYM[r.m]} ${hm(r.start)}–${hm(r.end)}</span>`).join("") : '<span class="hint">未入力</span>'}</div>${note ? `<span class="note">メモ：${esc(note)}</span>` : ""}</div></div>`;
        }
        if (a.memo) h += `<div class="memo">${esc(a.memo)}</div>`;
        h += `</div>`;
      }
      h += `</section>`;
    }
    h += `<p class="hint">${N}人が入力済み${N ? "：" + S.answers.map((a) => esc(a.name)).join("、") : ""}</p>`;

    h += `<section class="panel"><h2>メンバーに送る</h2>
    <div class="linkbox"><input type="text" id="share" readonly value="${esc(shareUrl())}" aria-label="共有リンク"><button class="btn sm" data-act="copy-link">リンクをコピー</button></div>
    <button class="btn sm" data-act="copy-invite" style="align-self:flex-start">案内文つきでコピー</button></section>`;

    h += `<section class="panel"><h2>オーナー用</h2>`;
    if (S.owner) {
      h += `<p class="small muted">オーナーとしてログイン中です。メンバー別の一覧から、いたずらの回答を削除できます。</p>
      <div class="row"><a class="btn sm" href="${link({ v: "edit" })}">日付・時間を編集</a><button class="btn sm" data-act="owner-logout">ログアウト</button></div>`;
    } else if (S.ownerOpen) {
      h += `<label class="f">オーナー用パスワード<input type="password" id="o-pass" autocomplete="current-password"></label><p class="status err" id="o-st" role="alert"></p>
      <div class="row"><button class="btn primary sm" data-act="owner-login">ログイン</button><button class="btn sm" data-act="owner-close">やめる</button></div>`;
    } else {
      h += `<button class="linkbtn" data-act="owner-open" style="align-self:flex-start">オーナーとしてログイン（日付の編集・削除）</button>`;
    }
    h += `</section>`;
    if (S.err === "net")
      h += `<p class="status err">最新の状態を読み込めませんでした。表示が古い可能性があります。</p>`;
    app.innerHTML = h + `</div>`;
  }

  /* ---------- 入力画面 ---------- */
  function renderAnswer(answerId) {
    const ev = S.ev;
    if (answerId) {
      const a = S.answers.find((x) => x.id === answerId);
      if (!a)
        return msg("回答が見つかりません", "削除された可能性があります。");
      const ver = myVerFor(answerId);
      if (!ver) {
        S.nextUnlock = answerId;
        S.tab = "list";
        go(link());
        return;
      }
      if (!S.draft || S.draft.id !== answerId)
        S.draft = {
          id: a.id,
          isNew: false,
          ver,
          name: a.name,
          memo: a.memo || "",
          marks: structuredClone(a.marks || {}),
          notes: { ...(a.notes || {}) },
          cur: ev.dates[0],
          brush: "o",
          mode: "range",
          anchor: null,
          pat: false,
        };
    } else if (!S.draft || !S.draft.isNew) {
      S.draft = {
        id: null,
        isNew: true,
        name: LS.get("chosei.name", ""),
        memo: "",
        marks: {},
        notes: {},
        cur: ev.dates[0],
        brush: "o",
        mode: "range",
        anchor: null,
        p1: "",
        p2: "",
        rem: true,
        pat: false,
      };
    }
    if (!ev.dates.includes(S.draft.cur)) S.draft.cur = ev.dates[0];
    paintAnswer();
  }

  function paintAnswer() {
    const ev = S.ev,
      D = S.draft,
      slots = slotsOf(ev),
      day = D.marks[D.cur] || {};
    const P = presets(),
      wd = dParts(D.cur).w;
    const hasWeekly = Object.values(P.weekly).some((r) => r && r.length);
    const filled = (d) => Object.keys(D.marks[d] || {}).length > 0;
    const lastIdx = slots.length - 1;
    let hint;
    if (D.mode === "range")
      hint =
        D.anchor !== null
          ? `<b style="color:var(--ac)">${hm(D.anchor)}〜</b> から、終わりのマスをタップ（同じマスをもう一度で1マスだけ）`
          : "下で ◎△× を選んで、始まりのマス → 終わりのマスの順にタップ";
    else
      hint =
        "下で ◎△× を選んで、マスをタップ（同じ印をもう一度タップで消える）";

    let h = `<div class="stack">
    <div><a class="linkbtn" href="${link()}">← ${esc(ev.title)}</a></div>
    <div><div class="eyebrow">${D.isNew ? "予定を入力" : "予定を編集"}</div><h1>${esc(ev.title)}</h1></div>
    <label class="f">名前<input type="text" id="a-name" maxlength="20" value="${esc(D.name)}" placeholder="例：さくら" autocomplete="nickname"></label>
    ${hasWeekly ? `<button class="btn" data-act="apply-weekly">いつもの予定（曜日）を全日程に反映</button>` : `<p class="hint">授業やバイトの時間は <a class="linkbtn" href="#v=presets" style="padding:0">いつもの予定</a> に登録しておくと、ワンタップで塗れます。</p>`}
    <div class="datebar" role="tablist" aria-label="日付">${ev.dates
      .map((d) => {
        const p = dParts(d);
        return `<button role="tab" data-act="day" data-d="${d}" aria-selected="${d === D.cur}"><span class="d">${p.m}/${p.d}</span><span class="w">${WD[p.w]}</span>${filled(d) ? '<span class="dot" aria-label="入力済み"></span>' : ""}</button>`;
      })
      .join("")}</div>
    <div class="panel" style="gap:10px">
      <div class="row between"><h2>${dLabel(D.cur)}</h2>
        <span class="seg"><button type="button" data-act="mode" data-v="range" aria-pressed="${D.mode === "range"}">範囲で塗る</button><button type="button" data-act="mode" data-v="one" aria-pressed="${D.mode === "one"}">1マスずつ</button></span></div>
      <p class="hint">${hint}</p>
      <div class="tgrid">${slots
        .map((t, i) => {
          const m = day[key(t)] || "";
          const inr = D.anchor !== null && t === D.anchor;
          return `<div class="trow"><span class="tl">${hm(t)}</span><button type="button" data-act="slot" data-t="${t}" class="${m} ${inr ? "anchor" : ""}" aria-label="${hm(t)}〜${hm(t + ev.step)} ${m ? LABEL[m] : "未入力"}"><span class="s">${m ? SYM[m] : ""}</span><span class="rng">${hm(t)}–${hm(t + ev.step)}</span></button></div>`;
        })
        .join("")}
        <div class="tend"><span class="tl">${hm(ev.endMin)}</span></div></div>
      <div class="tools">
        <button type="button" class="btn sm" data-act="fill" data-v="o">ぜんぶ◎</button>
        <button type="button" class="btn sm" data-act="fill" data-v="t">ぜんぶ△</button>
        <button type="button" class="btn sm" data-act="fill" data-v="x">ぜんぶ×</button>
        <button type="button" class="btn sm" data-act="fill" data-v="">クリア</button>
        ${ev.dates.indexOf(D.cur) > 0 ? `<button type="button" class="btn sm" data-act="copy-prev">前の日と同じ</button>` : ""}
      </div>
      <div class="sub">
        <div class="row">
          ${P.patterns.length ? `<select id="pat-sel" aria-label="パターン" style="flex:1 1 140px;width:auto"><option value="">パターンを選ぶ…</option>${P.patterns.map((p) => `<option value="${esc(p.id)}">${esc(p.name || "名前なし")}</option>`).join("")}</select><button class="btn sm" data-act="apply-pat">この日に当てはめる</button>` : '<span class="hint">よく使う塗り方は、パターンとして保存できます。</span>'}
        </div>
        ${
          D.pat
            ? `<div class="row"><input type="text" id="pat-name" maxlength="20" placeholder="例：授業の日" style="flex:1 1 140px;width:auto"><button class="btn sm primary" data-act="save-pat">保存</button><button class="btn sm" data-act="pat-cancel">やめる</button></div>`
            : `<div class="row"><button class="linkbtn" data-act="pat-open">この日の塗り方をパターンに保存</button><button class="linkbtn" data-act="set-weekly">${WD[wd]}曜のいつもの予定にする</button></div>`
        }
      </div>
      <label class="f">この日のメモ <span class="hint">任意</span><input type="text" id="a-note" maxlength="80" value="${esc(D.notes[D.cur] || "")}" placeholder="例：バイトで17時まで。オンラインなら参加可"></label>
    </div>
    <label class="f">全体のメモ <span class="hint">任意</span><textarea id="a-memo" maxlength="300" placeholder="例：12月後半は帰省するので参加できません">${esc(D.memo)}</textarea></label>
    ${
      D.isNew
        ? `<div class="panel"><h2>パスワードを決める</h2><p class="small muted">あとで自分の予定を直すときに使います。他の人には見えません。</p>
      <label class="f">パスワード<input type="password" id="a-p1" autocomplete="new-password" value="${esc(D.p1)}"></label>
      <label class="f">もう一度<input type="password" id="a-p2" autocomplete="new-password" value="${esc(D.p2)}"></label>
      <label class="check"><input type="checkbox" id="a-rem" ${D.rem ? "checked" : ""}>この端末では次から入力しない</label></div>`
        : ""
    }
    <p class="status err" id="a-st" role="alert"></p>
    ${
      D.isNew
        ? ""
        : S.pendingDel === "mine"
          ? `<div class="confirm"><p><b>自分の回答を削除しますか？</b></p><div class="row"><button class="btn danger" data-act="del-mine-yes">削除する</button><button class="btn" data-act="cancel-del">やめる</button></div></div>`
          : `<button class="linkbtn quiet" data-act="del-mine" style="align-self:flex-start">自分の回答を削除</button>`
    }
  </div>`;
    app.innerHTML = h;
    dock.innerHTML = `<div class="dock"><div class="dock-in"><div class="brush">${["o", "t", "x", "e"].map((b) => `<button type="button" class="${b}" data-act="brush" data-v="${b}" aria-pressed="${D.brush === b}">${b === "e" ? "消" : SYM[b]}<small>${b === "e" ? "消す" : LABEL[b]}</small></button>`).join("")}</div><button class="btn primary" data-act="save-ans" style="flex:none">${D.isNew ? "送信" : "保存"}</button></div></div>`;
  }
  function syncDraft() {
    const D = S.draft;
    if (!D) return;
    const v = (id) => document.getElementById(id);
    if (v("a-name")) D.name = v("a-name").value;
    if (v("a-memo")) D.memo = v("a-memo").value;
    if (v("a-note")) {
      const n = v("a-note").value;
      if (n) D.notes[D.cur] = n;
      else delete D.notes[D.cur];
    }
    if (v("a-p1")) {
      D.p1 = v("a-p1").value;
      D.p2 = v("a-p2").value;
      D.rem = v("a-rem").checked;
    }
  }
  function repaint() {
    const y = window.scrollY;
    paintAnswer();
    window.scrollTo(0, y);
  }
  function setCell(date, t, m) {
    const D = S.draft;
    const day = D.marks[date] || (D.marks[date] = {});
    if (m) day[key(t)] = m;
    else delete day[key(t)];
    if (!Object.keys(day).length) delete D.marks[date];
  }
  function applyRanges(date, ranges) {
    const ev = S.ev;
    let n = 0;
    for (const t of slotsOf(ev)) {
      let best = "";
      for (const r of ranges) {
        const s = toMin(r.s),
          e = toMin(r.e);
        if (s == null || e == null || e <= s) continue;
        if (s < t + ev.step && e > t && (!best || PRIO[r.m] > PRIO[best]))
          best = r.m;
      }
      if (best) {
        setCell(date, t, best);
        n++;
      }
    }
    return n;
  }
  function dayToRanges(date) {
    return rangesOf(S.draft.marks[date], S.ev).map((r) => ({
      s: fromMin(r.start),
      e: fromMin(r.end),
      m: r.m,
    }));
  }

  async function saveAnswer() {
    syncDraft();
    const D = S.draft,
      st = document.getElementById("a-st");
    const fail = (m, focusId) => {
      st.textContent = m;
      if (focusId) {
        const el = document.getElementById(focusId);
        el?.focus();
        el?.scrollIntoView({ block: "center" });
      } else st.scrollIntoView({ block: "center" });
    };
    const name = D.name.trim();
    if (!name) return fail("名前を入力してください。", "a-name");
    if (!Object.keys(D.marks).length)
      return fail("少なくとも1日は ◎△× を塗ってください。");
    if (D.isNew) {
      if (D.p1.length < 4)
        return fail("パスワードは4文字以上にしてください。", "a-p1");
      if (D.p1 !== D.p2) return fail("パスワードが一致しません。", "a-p2");
    }
    const btn = dock.querySelector('[data-act="save-ans"]');
    btn.disabled = true;
    st.textContent = "";
    LS.set("chosei.name", name);
    const body = { name, memo: D.memo.trim(), marks: D.marks, notes: D.notes };
    try {
      const c = await encryptObj(body);
      if (D.isNew) {
        const id = uuid(),
          ver = await verifier("member", D.p1, id);
        await rpc("create_answer", {
          p_id: id,
          p_event: S.id,
          p_cipher: c.cipher,
          p_iv: c.iv,
          p_pass: ver,
        });
        S.session[id] = ver;
        if (D.rem) rememberAnswer(id, ver);
        toast("送信しました");
      } else {
        const ok = await rpc("update_answer", {
          p_id: D.id,
          p_pass: D.ver,
          p_cipher: c.cipher,
          p_iv: c.iv,
        });
        if (!ok) {
          forgetAnswer(D.id);
          delete S.session[D.id];
          btn.disabled = false;
          return fail(
            "パスワードが確認できませんでした。一覧の「編集」からもう一度パスワードを入れてください。",
          );
        }
        toast("保存しました");
      }
      S.draft = null;
      await loadEvent(true);
      S.tab = "list";
      go(link());
    } catch (e) {
      btn.disabled = false;
      fail(
        e.kind === "net"
          ? "通信できませんでした。電波の良いところでもう一度お試しください。"
          : "保存できませんでした。時間をおいてもう一度お試しください。",
      );
    }
  }

  /* ---------- いつもの予定（プリセット） ---------- */
  function rangeRows(list, path) {
    return list
      .map(
        (r, i) => `<div class="rrow">
    <input type="time" step="300" value="${esc(r.s)}" data-pr="${path}.${i}.s" aria-label="開始">
    <span>〜</span>
    <input type="time" step="300" value="${esc(r.e)}" data-pr="${path}.${i}.e" aria-label="終了">
    <select data-pr="${path}.${i}.m" aria-label="印">${["x", "t", "o"].map((m) => `<option value="${m}" ${r.m === m ? "selected" : ""}>${SYM[m]} ${LABEL[m]}</option>`).join("")}</select>
    <button class="x" data-act="pr-del" data-path="${path}.${i}" aria-label="この時間を削除">×</button></div>`,
      )
      .join("");
  }
  function renderPresets() {
    const P = presets();
    let h = `<div class="stack">
    <div><a class="linkbtn" href="${S.id && S.ev ? link() : "#"}">← 戻る</a></div>
    <div><h1>いつもの予定</h1><p class="small muted">この端末だけに保存されます（他の人には見えません）。入力画面でワンタップで塗れます。</p></div>
    <div class="tabs" role="tablist"><button role="tab" data-act="pr-tab" data-v="weekly" aria-selected="${S.prTab === "weekly"}">曜日ごと</button><button role="tab" data-act="pr-tab" data-v="patterns" aria-selected="${S.prTab === "patterns"}">パターン</button></div>`;
    if (S.prTab === "weekly") {
      h += `<p class="hint">例：月曜 09:00〜12:10 × 授業。登録した時間に少しでもかかるマスに印が付きます（重なったら × → △ → ◎ の順に優先）。</p><section class="panel">`;
      for (const w of [1, 2, 3, 4, 5, 6, 0]) {
        const list = P.weekly[w] || [];
        h += `<div class="pr-day"><div class="row between"><h2>${WD[w]}曜日</h2><button class="btn sm" data-act="pr-add" data-path="w.${w}">＋ 時間を追加</button></div>${list.length ? rangeRows(list, "w." + w) : '<span class="hint">登録なし</span>'}</div>`;
      }
      h += `</section>`;
    } else {
      h += `<p class="hint">「授業の日」「バイトの日」など、名前をつけて保存しておくと、好きな日に当てはめられます。入力画面の「この日の塗り方をパターンに保存」からも作れます。</p>`;
      P.patterns.forEach((p, i) => {
        h += `<section class="panel"><div class="row"><input type="text" value="${esc(p.name)}" data-pr="p.${i}.name" maxlength="20" placeholder="パターンの名前" style="flex:1 1 140px;width:auto" aria-label="パターンの名前">
        ${S.pendingDel === "pat" + i ? `<button class="btn sm danger" data-act="pr-pat-del-yes" data-i="${i}">消す</button><button class="btn sm" data-act="cancel-del">やめる</button>` : `<button class="linkbtn quiet" data-act="pr-pat-del" data-i="${i}">削除</button>`}</div>
        ${rangeRows(p.ranges, "p." + i + ".ranges")}<button class="btn sm" data-act="pr-add" data-path="p.${i}" style="align-self:flex-start">＋ 時間を追加</button></section>`;
      });
      h += `<button class="btn" data-act="pr-pat-new">＋ パターンを作る</button>`;
    }
    app.innerHTML = h + `</div>`;
  }
  function prTarget(P, path) {
    // 'w.1' -> weekly[1] list, 'p.0' -> patterns[0].ranges
    const [k, a] = path.split(".");
    if (k === "w") return (P.weekly[a] ||= []);
    return P.patterns[+a].ranges;
  }

  /* ---------- 操作 ---------- */
  app.addEventListener("input", (e) => {
    const el = e.target;
    if (el.dataset.pr) {
      const P = presets(),
        parts = el.dataset.pr.split(".");
      if (parts[0] === "w") {
        const r = (P.weekly[parts[1]] || [])[+parts[2]];
        if (r) r[parts[3]] = el.value;
      } else if (parts[2] === "name") P.patterns[+parts[1]].name = el.value;
      else {
        const r = P.patterns[+parts[1]].ranges[+parts[3]];
        if (r) r[parts[4]] = el.value;
      }
      savePresets(P);
    }
  });
  app.addEventListener("change", (e) => {
    const el = e.target;
    if (!el.dataset.pr || el.tagName !== "SELECT") return;
    const P = presets(),
      parts = el.dataset.pr.split(".");
    if (parts[0] === "w") P.weekly[parts[1]][+parts[2]].m = el.value;
    else P.patterns[+parts[1]].ranges[+parts[3]].m = el.value;
    savePresets(P);
  });

  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const act = b.dataset.act,
      D = S.draft;
    switch (act) {
      // トップ
      case "forget-ev":
        LS.set(
          "chosei.events",
          myEvents().filter((x) => x.id !== b.dataset.id),
        );
        renderHome();
        break;
      // 作成フォーム
      case "cal": {
        if (e.detail !== 0)
          break; /* マウス・指は下のドラッグ処理で扱う。ここはキーボード操作用 */
        syncForm();
        const iso = b.dataset.iso,
          F = S.form;
        F.dates = F.dates.includes(iso)
          ? F.dates.filter((x) => x !== iso)
          : [...F.dates, iso].sort();
        keepScroll(() => renderForm(route().v === "edit"));
        document.querySelector(`[data-iso="${iso}"]`)?.focus();
        break;
      }
      case "cal-wd": {
        syncForm();
        const F = S.form,
          [Y, M] = F.ym,
          w = +b.dataset.w,
          days = new Date(Y, M + 1, 0).getDate();
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const list = [];
        for (let d = 1; d <= days; d++) {
          const dt = new Date(Y, M, d);
          if (dt.getDay() === w && dt >= today)
            list.push(`${Y}-${pad(M + 1)}-${pad(d)}`);
        }
        const allOn = list.length && list.every((x) => F.dates.includes(x));
        F.dates = allOn
          ? F.dates.filter((x) => !list.includes(x))
          : [...new Set([...F.dates, ...list])].sort();
        keepScroll(() => renderForm(route().v === "edit"));
        break;
      }
      case "month": {
        syncForm();
        let [y, m] = S.form.ym;
        m += +b.dataset.d;
        if (m < 0) {
          m = 11;
          y--;
        }
        if (m > 11) {
          m = 0;
          y++;
        }
        S.form.ym = [y, m];
        keepScroll(() => renderForm(route().v === "edit"));
        break;
      }
      case "step":
        syncForm();
        S.form.step = +b.dataset.v;
        if (S.form.step === 60 && (S.form.endMin - S.form.startMin) % 60)
          S.form.endMin += 30;
        keepScroll(() => renderForm(route().v === "edit"));
        break;
      case "del-event":
        syncForm();
        S.pendingDel = "event";
        keepScroll(() => renderForm(true));
        break;
      case "del-event-yes": {
        b.disabled = true;
        try {
          const ok = await rpc("delete_event", {
            p_id: S.id,
            p_owner: S.owner,
          });
          if (!ok) throw 0;
          LS.set(
            "chosei.events",
            myEvents().filter((x) => x.id !== S.id),
          );
          Object.assign(S, { id: null, keyB64: null, ev: null });
          toast("削除しました");
          go("#");
        } catch (err) {
          b.disabled = false;
          toast("削除できませんでした");
        }
        break;
      }
      case "cancel-del":
        S.pendingDel = null;
        if (route().v === "answer") {
          syncDraft();
          repaint();
        } else if (route().v === "edit") {
          syncForm();
          keepScroll(() => renderForm(true));
        } else keepScroll(render);
        break;
      // 共有
      case "copy-link":
        copyText(shareUrl(), document.getElementById("share"));
        break;
      case "copy-invite":
        copyText(inviteText(), document.getElementById("share"));
        break;
      // 一覧
      case "tab":
        S.tab = b.dataset.v;
        S.sel = null;
        keepScroll(render);
        break;
      case "cell": {
        const d = b.dataset.d,
          t = +b.dataset.t;
        S.sel = S.sel && S.sel.d === d && S.sel.t === t ? null : { d, t };
        keepScroll(render);
        break;
      }
      case "open-mine":
        go(link({ v: "answer", a: b.dataset.id }));
        break;
      case "unlock":
        S.unlockFor = b.dataset.id;
        keepScroll(render);
        setTimeout(() => document.getElementById("u-pass")?.focus(), 0);
        break;
      case "unlock-cancel":
        S.unlockFor = null;
        keepScroll(render);
        break;
      case "unlock-go": {
        const id = b.dataset.id,
          pass = document.getElementById("u-pass").value,
          st = document.getElementById("u-st");
        if (!pass) {
          st.textContent = "パスワードを入力してください。";
          break;
        }
        b.disabled = true;
        try {
          const ver = await verifier("member", pass, id);
          const ok = await rpc("check_answer", { p_id: id, p_pass: ver });
          if (!ok) {
            b.disabled = false;
            st.textContent = "パスワードが違います。";
            break;
          }
          S.session[id] = ver;
          if (document.getElementById("u-rem").checked) rememberAnswer(id, ver);
          S.unlockFor = null;
          go(link({ v: "answer", a: id }));
        } catch (err) {
          b.disabled = false;
          st.textContent = "確認できませんでした。通信状態を確認してください。";
        }
        break;
      }
      case "owner-open":
        S.ownerOpen = true;
        keepScroll(render);
        setTimeout(() => document.getElementById("o-pass")?.focus(), 0);
        break;
      case "owner-close":
        S.ownerOpen = false;
        keepScroll(render);
        break;
      case "owner-login": {
        const pass = document.getElementById("o-pass").value,
          st = document.getElementById("o-st");
        if (!pass) {
          st.textContent = "パスワードを入力してください。";
          break;
        }
        b.disabled = true;
        try {
          const ver = await verifier("owner", pass);
          const ok = await rpc("check_owner", { p_id: S.id, p_owner: ver });
          if (!ok) {
            b.disabled = false;
            st.textContent = "パスワードが違います。";
            break;
          }
          S.owner = ver;
          S.ownerOpen = false;
          rememberEvent("owner");
          toast("オーナーとしてログインしました");
          keepScroll(render);
        } catch (err) {
          b.disabled = false;
          st.textContent = "確認できませんでした。通信状態を確認してください。";
        }
        break;
      }
      case "owner-logout":
        S.owner = null;
        keepScroll(render);
        break;
      case "owner-del-ans":
        S.pendingDel = b.dataset.id;
        keepScroll(render);
        break;
      case "owner-del-ans-yes": {
        b.disabled = true;
        try {
          const ok = await rpc("owner_delete_answer", {
            p_event: S.id,
            p_owner: S.owner,
            p_answer: b.dataset.id,
          });
          if (!ok) throw 0;
          S.pendingDel = null;
          toast("削除しました");
          await loadEvent(true);
          keepScroll(render);
        } catch (err) {
          b.disabled = false;
          toast("削除できませんでした");
        }
        break;
      }
      // 入力画面
      case "day":
        syncDraft();
        D.cur = b.dataset.d;
        D.anchor = null;
        D.pat = false;
        repaint();
        requestAnimationFrame(() =>
          document
            .querySelector('.datebar [aria-selected="true"]')
            ?.scrollIntoView({ inline: "center", block: "nearest" }),
        );
        break;
      case "mode":
        syncDraft();
        D.mode = b.dataset.v;
        D.anchor = null;
        repaint();
        break;
      case "brush":
        D.brush = b.dataset.v;
        dock
          .querySelectorAll('[data-act="brush"]')
          .forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
        break;
      case "slot": {
        syncDraft();
        const t = +b.dataset.t,
          val = D.brush === "e" ? "" : D.brush;
        if (D.mode === "one") {
          const cur = (D.marks[D.cur] || {})[key(t)] || "";
          setCell(D.cur, t, cur === val ? "" : val);
        } else if (D.anchor === null) {
          D.anchor = t;
        } else {
          const a = Math.min(D.anchor, t),
            z = Math.max(D.anchor, t);
          for (const s of slotsOf(S.ev))
            if (s >= a && s <= z) setCell(D.cur, s, val);
          D.anchor = null;
        }
        repaint();
        break;
      }
      case "fill":
        syncDraft();
        for (const s of slotsOf(S.ev)) setCell(D.cur, s, b.dataset.v);
        D.anchor = null;
        repaint();
        break;
      case "copy-prev": {
        syncDraft();
        const prev = S.ev.dates[S.ev.dates.indexOf(D.cur) - 1];
        if (D.marks[prev]) D.marks[D.cur] = { ...D.marks[prev] };
        else delete D.marks[D.cur];
        D.anchor = null;
        repaint();
        break;
      }
      case "apply-weekly": {
        syncDraft();
        const P = presets();
        let days = 0;
        for (const d of S.ev.dates) {
          const r = P.weekly[dParts(d).w];
          if (r && r.length && applyRanges(d, r)) days++;
        }
        repaint();
        toast(
          days
            ? `${days}日分に反映しました`
            : "この調整の時間帯に重なる予定はありませんでした",
        );
        break;
      }
      case "apply-pat": {
        syncDraft();
        const id = document.getElementById("pat-sel").value;
        if (!id) {
          toast("パターンを選んでください");
          break;
        }
        const p = presets().patterns.find((x) => x.id === id);
        const n = p ? applyRanges(D.cur, p.ranges) : 0;
        repaint();
        toast(
          n
            ? `「${p.name}」を当てはめました`
            : "この日の時間帯に重なる時間がありませんでした",
        );
        break;
      }
      case "pat-open":
        syncDraft();
        if (!D.marks[D.cur]) {
          toast("先にこの日を塗ってください");
          break;
        }
        D.pat = true;
        repaint();
        setTimeout(() => document.getElementById("pat-name")?.focus(), 0);
        break;
      case "pat-cancel":
        syncDraft();
        D.pat = false;
        repaint();
        break;
      case "save-pat": {
        const name = document.getElementById("pat-name").value.trim();
        syncDraft();
        if (!name) {
          toast("パターンの名前を入れてください");
          break;
        }
        const P = presets();
        P.patterns.push({ id: uuid(), name, ranges: dayToRanges(D.cur) });
        savePresets(P);
        D.pat = false;
        repaint();
        toast(`「${name}」を保存しました`);
        break;
      }
      case "set-weekly": {
        syncDraft();
        if (!D.marks[D.cur]) {
          toast("先にこの日を塗ってください");
          break;
        }
        const P = presets(),
          w = dParts(D.cur).w;
        P.weekly[w] = dayToRanges(D.cur);
        savePresets(P);
        repaint();
        toast(`${WD[w]}曜のいつもの予定に登録しました`);
        break;
      }
      case "save-ans":
        saveAnswer();
        break;
      case "del-mine":
        syncDraft();
        S.pendingDel = "mine";
        repaint();
        break;
      case "del-mine-yes": {
        b.disabled = true;
        try {
          const ok = await rpc("delete_answer", { p_id: D.id, p_pass: D.ver });
          if (!ok) throw 0;
          forgetAnswer(D.id);
          delete S.session[D.id];
          S.draft = null;
          S.pendingDel = null;
          toast("削除しました");
          await loadEvent(true);
          go(link());
        } catch (err) {
          b.disabled = false;
          toast("削除できませんでした");
        }
        break;
      }
      // プリセット
      case "pr-tab":
        S.prTab = b.dataset.v;
        S.pendingDel = null;
        renderPresets();
        break;
      case "pr-add": {
        const P = presets();
        const list = prTarget(P, b.dataset.path);
        const last = list[list.length - 1];
        list.push(
          last
            ? {
                s: last.e,
                e: fromMin(Math.min(toMin(last.e) + 90, 24 * 60 - 5)),
                m: last.m,
              }
            : { s: "09:00", e: "10:30", m: "x" },
        );
        savePresets(P);
        keepScroll(renderPresets);
        break;
      }
      case "pr-del": {
        const P = presets();
        const parts = b.dataset.path.split(".");
        const i = +parts.pop();
        prTarget(P, parts.join(".")).splice(i, 1);
        savePresets(P);
        keepScroll(renderPresets);
        break;
      }
      case "pr-pat-new": {
        const P = presets();
        P.patterns.push({
          id: uuid(),
          name: "",
          ranges: [{ s: "09:00", e: "12:10", m: "x" }],
        });
        savePresets(P);
        renderPresets();
        window.scrollTo(0, document.body.scrollHeight);
        break;
      }
      case "pr-pat-del":
        S.pendingDel = "pat" + b.dataset.i;
        keepScroll(renderPresets);
        break;
      case "pr-pat-del-yes": {
        const P = presets();
        P.patterns.splice(+b.dataset.i, 1);
        savePresets(P);
        S.pendingDel = null;
        keepScroll(renderPresets);
        break;
      }
    }
  });
  /* ---------- カレンダーをなぞって選ぶ ---------- */
  // 押した日が未選択なら「選ぶ」、選択済みなら「外す」。押した日から今指がある日までの連続した日に適用する。
  let calDrag = null;
  const calBtnAt = (x, y) => {
    const el = document.elementFromPoint(x, y);
    return el && el.closest ? el.closest("#cal button[data-iso]") : null;
  };
  function calPaint(toIso) {
    const F = S.form,
      D = calDrag;
    const a = D.anchor < toIso ? D.anchor : toIso,
      z = D.anchor < toIso ? toIso : D.anchor;
    const set = new Set(D.base);
    document.querySelectorAll("#cal button[data-iso]").forEach((btn) => {
      const iso = btn.dataset.iso;
      if (iso >= a && iso <= z) {
        if (D.add) set.add(iso);
        else set.delete(iso);
      }
    });
    F.dates = [...set].sort();
    document
      .querySelectorAll("#cal button[data-iso]")
      .forEach((btn) =>
        btn.setAttribute("aria-pressed", String(set.has(btn.dataset.iso))),
      );
  }
  function calChips() {
    const el = document.getElementById("cal-chips");
    if (!el) return;
    el.innerHTML = S.form.dates.length
      ? S.form.dates
          .map((d) => `<span class="chip">${dLabel(d)}</span>`)
          .join("")
      : '<span class="hint">まだ日付が選ばれていません</span>';
  }
  document.addEventListener("pointerdown", (e) => {
    const btn = e.target.closest && e.target.closest("#cal button[data-iso]");
    if (!btn || !S.form || e.button > 0) return;
    e.preventDefault();
    syncForm();
    const iso = btn.dataset.iso;
    calDrag = {
      id: e.pointerId,
      anchor: iso,
      add: !S.form.dates.includes(iso),
      base: [...S.form.dates],
    };
    try {
      btn.releasePointerCapture(e.pointerId);
    } catch (_) {}
    calPaint(iso);
  });
  document.addEventListener("pointermove", (e) => {
    if (!calDrag || e.pointerId !== calDrag.id) return;
    const btn = calBtnAt(e.clientX, e.clientY);
    if (btn) calPaint(btn.dataset.iso);
  });
  const calEnd = (e) => {
    if (!calDrag || e.pointerId !== calDrag.id) return;
    calDrag = null;
    calChips();
  };
  document.addEventListener("pointerup", calEnd);
  document.addEventListener("pointercancel", calEnd);

  function keepScroll(fn) {
    const y = window.scrollY;
    fn();
    window.scrollTo(0, y);
  }
})();
