-- =====================================================================
-- みんなの日程調整 : Supabase 用セットアップ SQL
-- Supabase の「SQL Editor」にこのファイルの中身を全部貼って「Run」してください。
--
-- しくみ
--  * 調整の中身（タイトル・日付・名前・回答・メモ）はブラウザで暗号化されてから届くので、
--    ここに保存されるのは読めない暗号文だけです。鍵は共有リンクの # 以降にあり、
--    サーバーには送られません。
--  * パスワードもブラウザで「鍵＋パスワード」から作った確認用の値に変換され、
--    さらにここで bcrypt でハッシュ化して保存します。元のパスワードは誰にも見えません。
--  * テーブルへの直接アクセスは禁止し、下の関数経由でしか読み書きできません。
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.events (
  id          text primary key check (length(id) between 16 and 64),
  cipher      text not null check (length(cipher) < 100000),
  iv          text not null check (length(iv) < 64),
  owner_hash  text not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.answers (
  id          uuid primary key,
  event_id    text not null references public.events(id) on delete cascade,
  cipher      text not null check (length(cipher) < 200000),
  iv          text not null check (length(iv) < 64),
  pass_hash   text not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists answers_event_id_idx on public.answers(event_id);

-- 直接アクセスは全面禁止（ポリシーを作らないので RLS で全部拒否される）
alter table public.events  enable row level security;
alter table public.answers enable row level security;
revoke all on public.events  from anon, authenticated;
revoke all on public.answers from anon, authenticated;

-- ---------------------------------------------------------------------
-- 調整（イベント）
-- ---------------------------------------------------------------------
create or replace function public.create_event(p_id text, p_cipher text, p_iv text, p_owner text)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if length(coalesce(p_owner,'')) < 20 then raise exception 'bad owner verifier'; end if;
  insert into events(id, cipher, iv, owner_hash)
  values (p_id, p_cipher, p_iv, crypt(p_owner, gen_salt('bf', 8)));
end $$;

create or replace function public.get_event(p_id text)
returns json language sql stable security definer set search_path = public, extensions as $$
  select json_build_object(
    'event', (select json_build_object('cipher', e.cipher, 'iv', e.iv, 'updated_at', e.updated_at)
              from events e where e.id = p_id),
    'answers', coalesce((select json_agg(json_build_object(
                  'id', a.id, 'cipher', a.cipher, 'iv', a.iv,
                  'created_at', a.created_at, 'updated_at', a.updated_at) order by a.created_at)
                from answers a where a.event_id = p_id), '[]'::json)
  );
$$;

create or replace function public.check_owner(p_id text, p_owner text)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists(select 1 from events where id = p_id and owner_hash = crypt(p_owner, owner_hash));
$$;

create or replace function public.update_event(p_id text, p_owner text, p_cipher text, p_iv text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  update events set cipher = p_cipher, iv = p_iv, updated_at = now()
   where id = p_id and owner_hash = crypt(p_owner, owner_hash);
  return found;
end $$;

create or replace function public.delete_event(p_id text, p_owner text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  delete from events where id = p_id and owner_hash = crypt(p_owner, owner_hash);
  return found;
end $$;

-- ---------------------------------------------------------------------
-- メンバーの回答
-- ---------------------------------------------------------------------
create or replace function public.create_answer(p_id uuid, p_event text, p_cipher text, p_iv text, p_pass text)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if length(coalesce(p_pass,'')) < 20 then raise exception 'bad verifier'; end if;
  if not exists(select 1 from events where id = p_event) then raise exception 'event not found'; end if;
  if (select count(*) from answers where event_id = p_event) >= 300 then raise exception 'too many answers'; end if;
  insert into answers(id, event_id, cipher, iv, pass_hash)
  values (p_id, p_event, p_cipher, p_iv, crypt(p_pass, gen_salt('bf', 8)));
end $$;

create or replace function public.check_answer(p_id uuid, p_pass text)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists(select 1 from answers where id = p_id and pass_hash = crypt(p_pass, pass_hash));
$$;

create or replace function public.update_answer(p_id uuid, p_pass text, p_cipher text, p_iv text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  update answers set cipher = p_cipher, iv = p_iv, updated_at = now()
   where id = p_id and pass_hash = crypt(p_pass, pass_hash);
  return found;
end $$;

create or replace function public.delete_answer(p_id uuid, p_pass text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  delete from answers where id = p_id and pass_hash = crypt(p_pass, pass_hash);
  return found;
end $$;

-- オーナーがメンバーの回答を消す（いたずら書き対策）
create or replace function public.owner_delete_answer(p_event text, p_owner text, p_answer uuid)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  if not exists(select 1 from events where id = p_event and owner_hash = crypt(p_owner, owner_hash)) then
    return false;
  end if;
  delete from answers where id = p_answer and event_id = p_event;
  return found;
end $$;

-- 公開キー（anon）から呼べるのは上の関数だけ
revoke all on function public.create_event(text,text,text,text)            from public;
revoke all on function public.get_event(text)                              from public;
revoke all on function public.check_owner(text,text)                       from public;
revoke all on function public.update_event(text,text,text,text)            from public;
revoke all on function public.delete_event(text,text)                      from public;
revoke all on function public.create_answer(uuid,text,text,text,text)      from public;
revoke all on function public.check_answer(uuid,text)                      from public;
revoke all on function public.update_answer(uuid,text,text,text)           from public;
revoke all on function public.delete_answer(uuid,text)                     from public;
revoke all on function public.owner_delete_answer(text,text,uuid)          from public;

grant execute on function public.create_event(text,text,text,text)         to anon, authenticated;
grant execute on function public.get_event(text)                           to anon, authenticated;
grant execute on function public.check_owner(text,text)                    to anon, authenticated;
grant execute on function public.update_event(text,text,text,text)         to anon, authenticated;
grant execute on function public.delete_event(text,text)                   to anon, authenticated;
grant execute on function public.create_answer(uuid,text,text,text,text)   to anon, authenticated;
grant execute on function public.check_answer(uuid,text)                   to anon, authenticated;
grant execute on function public.update_answer(uuid,text,text,text)        to anon, authenticated;
grant execute on function public.delete_answer(uuid,text)                  to anon, authenticated;
grant execute on function public.owner_delete_answer(text,text,uuid)       to anon, authenticated;
