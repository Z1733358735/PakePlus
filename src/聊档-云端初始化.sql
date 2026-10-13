-- 聊档云同步 v2：在 Supabase SQL Editor 运行一次
-- 聊天正文、标题、标签等保存在私有 RLS 表；图片/PDF 附件保存在私有 Storage bucket。
-- 客户端只可使用 publishable/anon key，绝不要在网页里配置 service_role/secret key。

create table if not exists public.liaodang_records (
  user_id uuid not null references auth.users(id) on delete cascade,
  id text not null,
  payload jsonb not null default '{}'::jsonb,
  modified_at timestamptz not null default now(),
  deleted boolean not null default false,
  primary key (user_id, id)
);
create index if not exists liaodang_records_updated_idx on public.liaodang_records(user_id, modified_at);

create table if not exists public.liaodang_categories (
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  modified_at timestamptz not null default now(),
  deleted boolean not null default false,
  primary key (user_id, name)
);

alter table public.liaodang_records enable row level security;
alter table public.liaodang_categories enable row level security;
revoke all on public.liaodang_records from anon, authenticated;
revoke all on public.liaodang_categories from anon, authenticated;
grant select, insert, update on public.liaodang_records to authenticated;
grant select, insert, update on public.liaodang_categories to authenticated;

-- 重复执行此脚本时，先删除同名策略再建立。
drop policy if exists "ld_record_read" on public.liaodang_records;
create policy "ld_record_read" on public.liaodang_records for select to authenticated
  using ((select auth.uid()) = user_id);
drop policy if exists "ld_record_create" on public.liaodang_records;
create policy "ld_record_create" on public.liaodang_records for insert to authenticated
  with check ((select auth.uid()) = user_id);
drop policy if exists "ld_record_update" on public.liaodang_records;
create policy "ld_record_update" on public.liaodang_records for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

drop policy if exists "ld_category_read" on public.liaodang_categories;
create policy "ld_category_read" on public.liaodang_categories for select to authenticated
  using ((select auth.uid()) = user_id);
drop policy if exists "ld_category_create" on public.liaodang_categories;
create policy "ld_category_create" on public.liaodang_categories for insert to authenticated
  with check ((select auth.uid()) = user_id);
drop policy if exists "ld_category_update" on public.liaodang_categories;
create policy "ld_category_update" on public.liaodang_categories for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

-- 仅较新版本获准覆盖旧版本，避免脱机设备上传旧数据时覆盖新数据。
create or replace function public.liaodang_put_record(
  p_id text, p_payload jsonb, p_modified_at timestamptz, p_deleted boolean
) returns void language plpgsql security invoker set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not authenticated'; end if;
  insert into public.liaodang_records(user_id, id, payload, modified_at, deleted)
  values (auth.uid(), p_id, coalesce(p_payload, '{}'::jsonb), p_modified_at, p_deleted)
  on conflict (user_id, id) do update
    set payload = excluded.payload,
        modified_at = excluded.modified_at,
        deleted = excluded.deleted
    where liaodang_records.modified_at < excluded.modified_at;
end $$;

create or replace function public.liaodang_put_category(
  p_name text, p_modified_at timestamptz, p_deleted boolean
) returns void language plpgsql security invoker set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not authenticated'; end if;
  insert into public.liaodang_categories(user_id, name, modified_at, deleted)
  values (auth.uid(), p_name, p_modified_at, p_deleted)
  on conflict (user_id, name) do update
    set modified_at = excluded.modified_at,
        deleted = excluded.deleted
    where liaodang_categories.modified_at < excluded.modified_at;
end $$;

revoke all on function public.liaodang_put_record(text,jsonb,timestamptz,boolean) from public, anon;
revoke all on function public.liaodang_put_category(text,timestamptz,boolean) from public, anon;
grant execute on function public.liaodang_put_record(text,jsonb,timestamptz,boolean) to authenticated;
grant execute on function public.liaodang_put_category(text,timestamptz,boolean) to authenticated;

insert into storage.buckets (id, name, public, file_size_limit)
values ('liaodang-private', 'liaodang-private', false, 52428800)
on conflict (id) do update set public=false;

-- 严格限制到用户自己 UUID 的文件夹。
drop policy if exists "ld_storage_read" on storage.objects;
create policy "ld_storage_read" on storage.objects for select to authenticated
  using (bucket_id='liaodang-private' and (storage.foldername(name))[1] = (select auth.uid()::text));
drop policy if exists "ld_storage_upload" on storage.objects;
create policy "ld_storage_upload" on storage.objects for insert to authenticated
  with check (bucket_id='liaodang-private' and (storage.foldername(name))[1] = (select auth.uid()::text));
drop policy if exists "ld_storage_delete" on storage.objects;
create policy "ld_storage_delete" on storage.objects for delete to authenticated
  using (bucket_id='liaodang-private' and (storage.foldername(name))[1] = (select auth.uid()::text));
