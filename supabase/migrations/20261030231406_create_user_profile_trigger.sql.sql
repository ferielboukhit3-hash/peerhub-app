/*
# Create user profile trigger

1. Purpose
- The profiles table stores each user's display name and headline.
- A profile row must exist for every user so the dashboard can load their name.
- Without an automatic profile row, sign-up can fail or the dashboard breaks for new users.

2. Changes
- Recreate the `public.handle_new_user()` SECURITY DEFINER function.
- It inserts a profile row using the `display_name` from the sign-up metadata,
  falling back to the part of the email before `@` if no name was provided.
  Uses `ON CONFLICT (id) DO NOTHING` so it is safe to re-run for existing users.
- Recreate the `on_auth_user_created` trigger on `auth.users` that calls this function
  whenever a new auth user is created (i.e. on every sign-up).
- Revoke public/anon/authenticated execute so app users cannot call it directly;
  it should only run via the trigger.

3. Security
- The function is SECURITY DEFINER so it can insert into `profiles` (which users
  cannot INSERT into directly) while running as the table owner.
- `search_path = public` to avoid schema-injection.
- Trigger fires AFTER INSERT on auth.users; the profile row is created server-side
  with no extra client call required.
*/

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, display_name)
  VALUES (
    NEW.id,
    COALESCE(
      NULLIF(btrim(NEW.raw_user_meta_data->>'display_name'), ''),
      split_part(NEW.email, '@', 1)
    )
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
