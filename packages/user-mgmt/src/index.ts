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

// ===== 3. 获取用户信息 =====
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

// ===== 4. 更新个人资料 =====
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

// ===== 6. 个人中心 HTML（深色毛玻璃） =====
async function handleAccount(request: Request, env: Env) {
    const url = new URL(request.url);
    const username = url.searchParams.get('username') || 'test123';

    const user = await getUser(env, username);
    if (!user) {
        return new Response('用户不存在', { status: 404 });
    }

    if (request.method === 'POST' && url.searchParams.get('action') === 'edit') {
        try {
            const formData = await request.formData();
            const bio = formData.get('bio') || '';
            const avatar = formData.get('avatar') || '';
            await env.usersDB.prepare('UPDATE users SET bio = ?, avatar = ? WHERE username = ?')
                .bind(bio, avatar, username).run();
            return new Response(null, {
                status: 302,
                headers: { 'Location': `/account?username=${username}` }
            });
        } catch (e) {
            return new Response('更新失败', { status: 500 });
        }
    }

    const bgImage = 'https://raw.githubusercontent.com/HSDCofficial/users-manage-react/main/public/bg.jpg';

    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>个人中心 · 凉宫数据</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: url('${bgImage}') center/cover fixed, #1a1a2e;
            padding: 20px;
        }
        .glass {
            background: rgba(20,20,35,0.85);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 32px;
            padding: 32px 24px;
            max-width: 420px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.6);
            color: #fff;
            text-align: center;
        }
        .avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            object-fit: cover;
            border: 3px solid rgba(255,255,255,0.2);
            margin: 0 auto 16px;
        }
        h1 { font-size: 26px; font-weight: 600; margin-bottom: 6px; }
        .bio { font-size: 15px; opacity: 0.85; margin-bottom: 16px; }
        .badge { display: inline-block; background: rgba(59,130,246,0.6); padding: 4px 14px; border-radius: 20px; font-size: 13px; margin-bottom: 16px; }
        .field { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid rgba(255,255,255,0.08); }
        .field-label { opacity: 0.6; font-size: 14px; }
        .field-value { font-weight: 500; font-size: 14px; }
        .btn {
            display: inline-block;
            margin-top: 20px;
            background: rgba(255,255,255,0.1);
            border: 1px solid rgba(255,255,255,0.15);
            padding: 10px 24px;
            border-radius: 40px;
            color: #fff;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
            text-decoration: none;
            font-size: 14px;
        }
        .btn:hover { background: rgba(255,255,255,0.2); }
        .btn-primary { background: rgba(59,130,246,0.5); border-color: rgba(59,130,246,0.3); }
        .btn-primary:hover { background: rgba(59,130,246,0.7); }
        .edit-form { margin-top: 20px; text-align: left; }
        .edit-form label { display: block; font-size: 14px; opacity: 0.7; margin-bottom: 4px; }
        .edit-form input, .edit-form textarea {
            width: 100%;
            padding: 10px 14px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.15);
            background: rgba(255,255,255,0.08);
            color: #fff;
            font-size: 14px;
            margin-bottom: 12px;
        }
        .edit-form input:focus, .edit-form textarea:focus {
            outline: none;
            border-color: rgba(255,255,255,0.3);
        }
        .edit-form textarea { resize: vertical; min-height: 60px; }
        .edit-form .btn-group { display: flex; gap: 10px; }
        .edit-form .btn-group .btn { flex: 1; text-align: center; margin-top: 0; }
        .back-link { display: block; margin-top: 16px; color: rgba(255,255,255,0.5); font-size: 13px; }
    </style>
</head>
<body>
    <div class="glass">
        <img src="${user.avatar || 'https://ui-avatars.com/api/?name=' + encodeURIComponent(user.username) + '&background=3b82f6&color=fff&size=128'}" alt="avatar" class="avatar" />
        <h1>${user.username}</h1>
        <div class="bio">${user.bio || '这个人很懒，什么都没写~'}</div>
        ${user.badge ? `<div class="badge">🏅 ${user.badge}</div>` : ''}
        <div style="text-align:left;margin-top:16px;">
            <div class="field"><span class="field-label">用户名</span><span class="field-value">${user.username}</span></div>
            <div class="field"><span class="field-label">简介</span><span class="field-value">${user.bio || '未设置'}</span></div>
            <div class="field"><span class="field-label">角色</span><span class="field-value">${user.role || '用户'}</span></div>
        </div>

        <button id="editBtn" class="btn btn-primary">✏️ 编辑资料</button>

        <div id="editForm" class="edit-form" style="display:none;">
            <form method="POST" action="?username=${username}&action=edit">
                <label>头像 URL</label>
                <input type="text" name="avatar" value="${user.avatar || ''}" placeholder="https://example.com/avatar.png" />
                <label>个人简介</label>
                <textarea name="bio" placeholder="写点什么吧...">${user.bio || ''}</textarea>
                <div class="btn-group">
                    <button type="submit" class="btn btn-primary">💾 保存</button>
                    <button type="button" id="cancelBtn" class="btn">取消</button>
                </div>
            </form>
        </div>

        <a href="?username=${user.username}" class="back-link">🔄 刷新</a>
    </div>

    <script>
        document.getElementById('editBtn').addEventListener('click', function() {
            document.getElementById('editForm').style.display = 'block';
            this.style.display = 'none';
        });
        document.getElementById('cancelBtn').addEventListener('click', function() {
            document.getElementById('editForm').style.display = 'none';
            document.getElementById('editBtn').style.display = 'inline-block';
        });
    </script>
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