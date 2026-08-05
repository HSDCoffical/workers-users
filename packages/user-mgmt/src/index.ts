import { AutoRouter, cors } from 'itty-router';
import { getSessionIdFromCookies, getUser, checkUserExists, storeUser, updatePassword } from './utils';
import { hashPassword, comparePassword } from './auth';
import { createSession, deleteSession, loadSession } from './session';
import { sendEmail } from './email';
import { Env, getForgotPasswordUrl, getRbacEnabled } from './env';
import { assignDefaultRole, getUserRoles } from './rbac';

// ===== CORS 配置 =====
const { preflight, corsify } = cors({
    origin: true,
    credentials: true,
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE'],
    maxAge: 84600,
});

const router = AutoRouter({
    before: [preflight],
    finally: [corsify],
});

// ===== 1. 注册 =====
async function handleRegister(request: Request, env: Env) {
    try {
        const { username, password } = await request.json();
        if (!username || !password) {
            return new Response(JSON.stringify({ error: 'Missing required fields' }), { status: 400 });
        }
        const exists = await checkUserExists(env, username);
        if (exists) {
            return new Response(JSON.stringify({ error: 'User already exists' }), { status: 409 });
        }
        const hashed = await hashPassword(password);
        const userId = await storeUser(env, { username, hashedPassword: hashed });
        if (getRbacEnabled(env)) {
            try { await assignDefaultRole(env, userId); } catch (e) {}
        }
        return new Response(JSON.stringify({ message: 'User registered successfully' }), { status: 201 });
    } catch (e) {
        return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500 });
    }
}

// ===== 2. 登录 =====
async function handleLogin(request: Request, env: Env) {
    try {
        const { username, password } = await request.json();
        if (!username || !password) {
            return new Response(JSON.stringify({ error: 'Missing credentials' }), { status: 400 });
        }
        const user = await getUser(env, username);
        if (!user) {
            return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401 });
        }

        // 兼容大小写密码字段
        let storedPassword = user.password || user.Password || user.passwd;
        if (!storedPassword) {
            console.error('User object has no password field:', JSON.stringify(user));
            return new Response(JSON.stringify({ error: 'User data corrupted' }), { status: 500 });
        }

        const match = await comparePassword(password, storedPassword);
        if (!match) {
            return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401 });
        }

        const sessionId = await createSession(env, { id: user.id, username: user.username });
        return new Response(JSON.stringify({ message: 'Login successful' }), {
            headers: { 'Set-Cookie': `cfw_session=${sessionId}; Secure; Path=/; SameSite=None; Max-Age=1800` }
        });
    } catch (e) {
        console.error('Login error:', e);
        return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500 });
    }
}

// ===== 3. 获取用户信息（支持 ?username= 参数） =====
async function handleLoadUser(request: Request, env: Env) {
    try {
        const url = new URL(request.url);
        const username = url.searchParams.get('username');
        if (!username) {
            return new Response(JSON.stringify({ error: 'Missing username parameter' }), { status: 400 });
        }
        const user = await getUser(env, username);
        if (!user) {
            return new Response(JSON.stringify({ error: 'User not found' }), { status: 404 });
        }
        const { password, ...safeUser } = user;
        return new Response(JSON.stringify(safeUser), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (e) {
        return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500 });
    }
}

// ===== 4. 更新个人资料（支持 ?username= 参数） =====
async function handleUpdateProfile(request: Request, env: Env) {
    try {
        const url = new URL(request.url);
        const username = url.searchParams.get('username');
        if (!username) {
            return new Response(JSON.stringify({ error: 'Missing username parameter' }), { status: 400 });
        }
        const { avatar, bio } = await request.json();
        const updates = [];
        const values = [];
        if (avatar !== undefined) { updates.push('avatar = ?'); values.push(avatar); }
        if (bio !== undefined) { updates.push('bio = ?'); values.push(bio); }
        if (updates.length === 0) {
            return new Response(JSON.stringify({ error: 'No fields to update' }), { status: 400 });
        }
        values.push(username);
        const query = `UPDATE users SET ${updates.join(', ')} WHERE username = ?`;
        await env.usersDB.prepare(query).bind(...values).run();
        return new Response(JSON.stringify({ message: 'Profile updated successfully' }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (e) {
        return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500 });
    }
}

// ===== 5. 登出 =====
async function handleLogout(request: Request, env: Env) {
    const sessionId = getSessionIdFromCookies(request);
    if (sessionId) { await deleteSession(env, sessionId); }
    return new Response(JSON.stringify({ message: 'Logout successful' }), {
        headers: { 'Set-Cookie': 'cfw_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;' }
    });
}

// ===== 6. 返回个人中心 HTML 页面 =====
async function handleAccount(request: Request, env: Env) {
    const url = new URL(request.url);
    const username = url.searchParams.get('username') || 'test123';

    const user = await getUser(env, username);
    if (!user) {
        return new Response('用户不存在', { status: 404 });
    }

    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>个人中心 · 凉宫数据</title>
    <style>
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background: #f0f4ff;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 16px;
        }
        .card {
            background: white;
            max-width: 400px;
            width: 100%;
            border-radius: 24px;
            padding: 32px 24px;
            box-shadow: 0 12px 40px rgba(0,0,0,0.08);
            text-align: center;
        }
        .avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            object-fit: cover;
            border: 3px solid #3b82f6;
            margin: 0 auto 16px;
        }
        h1 { font-size: 24px; margin: 8px 0; }
        .bio { color: #555; font-size: 14px; margin: 8px 0 16px; }
        .badge { display: inline-block; background: #3b82f6; color: white; font-size: 12px; padding: 4px 12px; border-radius: 20px; }
        .field { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }
        .field-label { color: #888; }
        .field-value { font-weight: 500; }
        .back { margin-top: 20px; color: #3b82f6; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <img src="${user.avatar || 'https://ui-avatars.com/api/?name=' + encodeURIComponent(user.username) + '&background=3b82f6&color=fff&size=128'}" alt="avatar" class="avatar" />
        <h1>${user.username}</h1>
        <div class="bio">${user.bio || '这个人很懒，什么都没写~'}</div>
        ${user.badge ? `<span class="badge">🏅 ${user.badge}</span>` : ''}
        <div style="margin-top:20px;text-align:left;">
            <div class="field"><span class="field-label">用户名</span><span class="field-value">${user.username}</span></div>
            <div class="field"><span class="field-label">简介</span><span class="field-value">${user.bio || '未设置'}</span></div>
            <div class="field"><span class="field-label">角色</span><span class="field-value">${user.role || '用户'}</span></div>
        </div>
        <a href="?username=${user.username}" class="back">刷新</a>
    </div>
</body>
</html>
    `;

    return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
}

// ===== 定义路由 =====
router
    .post('*/register', (req, env) => handleRegister(req, env))
    .post('*/login', (req, env) => handleLogin(req, env))
    .post('*/logout', (req, env) => handleLogout(req, env))
    .get('*/load-user', (req, env) => handleLoadUser(req, env))
    .put('*/update-profile', (req, env) => handleUpdateProfile(req, env))
    .get('*/account', (req, env) => handleAccount(req, env))
    .all('*', () => new Response('Not Found', { status: 404 }));

export default { ...router };