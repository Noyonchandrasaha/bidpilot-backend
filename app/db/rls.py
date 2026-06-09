from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


RLS_TABLES = [
    "roles",
    "permissions",
    "role_permissions",
    "users",
    "user_profiles",
    "user_sessions",
    "customer_segments",
    "customers",
    "customer_transactions",
    "notifications",
    "audit_logs",
    "file_uploads",
    "settings",
]


RLS_SQL = [
    "ALTER TABLE roles ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE permissions ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE role_permissions ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE users ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE customer_segments ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE customers ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE customer_transactions ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE file_uploads ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE settings ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE roles FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE permissions FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE role_permissions FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE users FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE user_profiles FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE user_sessions FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE customer_segments FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE customers FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE customer_transactions FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE notifications FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE file_uploads FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE settings FORCE ROW LEVEL SECURITY;",
    "DROP POLICY IF EXISTS rls_bypass_roles ON roles;",
    "CREATE POLICY rls_bypass_roles ON roles FOR ALL USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin') WITH CHECK (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin');",
    "DROP POLICY IF EXISTS rls_bypass_permissions ON permissions;",
    "CREATE POLICY rls_bypass_permissions ON permissions FOR ALL USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin') WITH CHECK (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin');",
    "DROP POLICY IF EXISTS rls_bypass_role_permissions ON role_permissions;",
    "CREATE POLICY rls_bypass_role_permissions ON role_permissions FOR ALL USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin') WITH CHECK (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin');",
    "DROP POLICY IF EXISTS rls_users_select ON users;",
    "CREATE POLICY rls_users_select ON users FOR SELECT USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR id::text = current_setting('app.current_user_id', true));",
    "DROP POLICY IF EXISTS rls_users_modify ON users;",
    "CREATE POLICY rls_users_modify ON users FOR UPDATE USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR id::text = current_setting('app.current_user_id', true)) WITH CHECK (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR id::text = current_setting('app.current_user_id', true));",
    "DROP POLICY IF EXISTS rls_user_profiles ON user_profiles;",
    "CREATE POLICY rls_user_profiles ON user_profiles FOR ALL USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR user_id::text = current_setting('app.current_user_id', true)) WITH CHECK (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR user_id::text = current_setting('app.current_user_id', true));",
    "DROP POLICY IF EXISTS rls_user_sessions ON user_sessions;",
    "CREATE POLICY rls_user_sessions ON user_sessions FOR ALL USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR user_id::text = current_setting('app.current_user_id', true)) WITH CHECK (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR user_id::text = current_setting('app.current_user_id', true));",
    "DROP POLICY IF EXISTS rls_customer_segments ON customer_segments;",
    "CREATE POLICY rls_customer_segments ON customer_segments FOR ALL USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin') WITH CHECK (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin');",
    "DROP POLICY IF EXISTS rls_customers ON customers;",
    "CREATE POLICY rls_customers ON customers FOR ALL USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR created_by_id::text = current_setting('app.current_user_id', true) OR updated_by_id::text = current_setting('app.current_user_id', true)) WITH CHECK (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR created_by_id::text = current_setting('app.current_user_id', true) OR updated_by_id::text = current_setting('app.current_user_id', true));",
    "DROP POLICY IF EXISTS rls_customer_transactions ON customer_transactions;",
    "CREATE POLICY rls_customer_transactions ON customer_transactions FOR ALL USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR created_by_id::text = current_setting('app.current_user_id', true)) WITH CHECK (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR created_by_id::text = current_setting('app.current_user_id', true));",
    "DROP POLICY IF EXISTS rls_notifications ON notifications;",
    "CREATE POLICY rls_notifications ON notifications FOR ALL USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR user_id::text = current_setting('app.current_user_id', true)) WITH CHECK (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR user_id::text = current_setting('app.current_user_id', true));",
    "DROP POLICY IF EXISTS rls_audit_logs ON audit_logs;",
    "CREATE POLICY rls_audit_logs ON audit_logs FOR SELECT USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR actor_id::text = current_setting('app.current_user_id', true));",
    "DROP POLICY IF EXISTS rls_file_uploads ON file_uploads;",
    "CREATE POLICY rls_file_uploads ON file_uploads FOR ALL USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR uploaded_by_id::text = current_setting('app.current_user_id', true)) WITH CHECK (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR uploaded_by_id::text = current_setting('app.current_user_id', true));",
    "DROP POLICY IF EXISTS rls_settings ON settings;",
    "CREATE POLICY rls_settings ON settings FOR ALL USING (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR user_id::text = current_setting('app.current_user_id', true) OR scope::text = 'SYSTEM') WITH CHECK (current_setting('app.rls_bypass', true) = 'on' OR current_setting('app.current_role', true) = 'admin' OR user_id::text = current_setting('app.current_user_id', true) OR scope::text = 'SYSTEM');",
]


async def bootstrap_rls(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        for stmt in RLS_SQL:
            await conn.execute(text(stmt))
