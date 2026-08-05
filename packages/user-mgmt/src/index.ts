import { AutoRouter, cors } from 'itty-router';
import { getSessionIdFromCookies, getUser, checkUserExists, storeUser, updatePassword } from './utils';
import { hashPassword, comparePassword } from './auth';
import { createSession, deleteSession, loadSession } from './session';
import { sendEmail } from './email';
import { Env, getForgotPasswordUrl, getRbacEnabled } from './env';
import { assignDefaultRole, getUserRoles } from './rbac';

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

// ===== 1. 注册（修复：返回 JSON，不依赖 session） =====
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

// ===== 2. 登录（修复：不依赖 session-state，直接返回成功） =====
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
            return new Response(JSON.stringify({ error: 'User data corrupted' }), { status: 500 });
        }
        const match = await comparePassword(password, storedPassword);
        if (!match) {
            return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401 });
        }
        // 登录成功，直接返回成功信息，不创建 session（避免超时）
        return new Response(JSON.stringify({ message: 'Login successful', username: user.username }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (e) {
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

// ===== 4. 更新个人资料（修复：支持修改用户名和密码） =====
async function handleUpdateProfile(request: Request, env: Env) {
    try {
        const url = new URL(request.url);
        const username = url.searchParams.get('username');
        if (!username) {
            return new Response(JSON.stringify({ error: 'Missing username parameter' }), { status: 400 });
        }
        const { avatar, bio, newUsername, newPassword } = await request.json();
        
        let updates = [];
        let values = [];
        
        if (avatar !== undefined) { updates.push('avatar = ?'); values.push(avatar); }
        if (bio !== undefined) { updates.push('bio = ?'); values.push(bio); }
        if (newUsername && newUsername !== username) { 
            updates.push('username = ?'); 
            values.push(newUsername); 
        }
        if (newPassword) { 
            const hashed = await hashPassword(newPassword);
            updates.push('password = ?'); 
            values.push(hashed); 
        }
        
        if (updates.length === 0) {
            return new Response(JSON.stringify({ error: 'No fields to update' }), { status: 400 });
        }
        
        values.push(username);
        const query = `UPDATE users SET ${updates.join(', ')} WHERE username = ?`;
        await env.usersDB.prepare(query).bind(...values).run();
        
        return new Response(JSON.stringify({ 
            message: 'Profile updated successfully',
            username: newUsername || username
        }), {
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

// ===== 6. 获取消息 =====
async function handleGetMessages(request: Request, env: Env) {
    const url = new URL(request.url);
    const username = url.searchParams.get('username');
    if (!username) {
        return new Response(JSON.stringify({ error: 'Missing username parameter' }), { status: 400 });
    }
    const result = await env.usersDB.prepare(
        'SELECT * FROM messages WHERE username = ? OR username = "all" ORDER BY created_at DESC LIMIT 50'
    ).bind(username).all();
    return new Response(JSON.stringify(result.results), {
        headers: { 'Content-Type': 'application/json' }
    });
}

// ===== 7. 个人中心 HTML =====
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
            const newUsername = formData.get('newUsername') || '';
            const newPassword = formData.get('newPassword') || '';

            let updates = [];
            let values = [];
            
            if (avatar) { updates.push('avatar = ?'); values.push(avatar); }
            if (bio !== undefined) { updates.push('bio = ?'); values.push(bio); }
            if (newUsername && newUsername !== username) { 
                updates.push('username = ?'); 
                values.push(newUsername); 
            }
            if (newPassword) { 
                const hashed = await hashPassword(newPassword);
                updates.push('password = ?'); 
                values.push(hashed); 
            }
            
            if (updates.length === 0) {
                return new Response('没有要更新的字段', { status: 400 });
            }
            
            values.push(username);
            const query = `UPDATE users SET ${updates.join(', ')} WHERE username = ?`;
            await env.usersDB.prepare(query).bind(...values).run();
            
            const redirectTo = newUsername || username;
            return new Response(null, {
                status: 302,
                headers: { 'Location': `/account?username=${redirectTo}` }
            });
        } catch (e) {
            return new Response('更新失败', { status: 500 });
        }
    }

    const messagesResult = await env.usersDB.prepare(
        'SELECT * FROM messages WHERE username = ? OR username = "all" ORDER BY created_at DESC LIMIT 20'
    ).bind(username).all();
    const messages = messagesResult.results || [];

    let messagesHtml = '';
    if (messages.length === 0) {
        messagesHtml = '<div style="text-align:center;padding:20px;color:#999;font-size:14px;">暂无消息</div>';
    } else {
        messagesHtml = messages.map(msg => `
            <div style="padding:10px 12px;margin-bottom:8px;background:rgba(255,255,255,0.5);border-radius:12px;border-left:3px solid ${msg.type === 'warning' ? '#f59e0b' : msg.type === 'danger' ? '#ef4444' : '#3b82f6'};">
                <div style="display:flex;justify-content:space-between;font-size:12px;color:#666;margin-bottom:4px;">
                    <span>${msg.title || '系统通知'}</span>
                    <span>${msg.created_at || ''}</span>
                </div>
                <div style="font-size:14px;color:#1a1a2e;">${msg.content}</div>
            </div>
        `).join('');
    }

    const bgImage = 'https://cdn.jsdelivr.net/gh/HSDCofficial/users-manage-react@main/public/bg.jpg';

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
            background: url('${bgImage}') center/cover fixed, #e8f0fe;
            padding: 20px;
        }
        .glass {
            background: rgba(255,255,255,0.25);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255,255,255,0.3);
            border-radius: 32px;
            padding: 32px 24px;
            max-width: 480px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.15);
            color: #1a1a2e;
            text-align: center;
        }
        .avatar {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            object-fit: cover;
            border: 3px solid rgba(255,255,255,0.6);
            margin: 0 auto 12px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.1);
        }
        h1 { font-size: 22px; font-weight: 600; margin-bottom: 4px; color: #1a1a2e; }
        .bio { font-size: 14px; opacity: 0.8; margin-bottom: 12px; color: #333; }
        .badge { display: inline-block; background: rgba(59,130,246,0.2); padding: 4px 14px; border-radius: 20px; font-size: 12px; color: #1a1a2e; margin-bottom: 12px; }
        .field { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid rgba(0,0,0,0.08); }
        .field-label { opacity: 0.6; font-size: 13px; color: #1a1a2e; }
        .field-value { font-weight: 500; font-size: 13px; color: #1a1a2e; }
        .section-title { font-size: 16px; font-weight: 600; margin: 20px 0 12px; text-align: left; color: #1a1a2e; }
        .btn {
            display: inline-block;
            margin-top: 16px;
            background: rgba(0,0,0,0.05);
            border: 1px solid rgba(0,0,0,0.1);
            padding: 8px 20px;
            border-radius: 40px;
            color: #1a1a2e;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
            text-decoration: none;
            font-size: 13px;
        }
        .btn:hover { background: rgba(0,0,0,0.1); }
        .btn-primary { background: rgba(59,130,246,0.15); border-color: rgba(59,130,246,0.2); }
        .btn-primary:hover { background: rgba(59,130,246,0.25); }
        .edit-form { margin-top: 16px; text-align: left; }
        .edit-form label { display: block; font-size: 13px; opacity: 0.7; margin-bottom: 4px; color: #1a1a2e; }
        .edit-form input, .edit-form textarea {
            width: 100%;
            padding: 8px 12px;
            border-radius: 12px;
            border: 1px solid rgba(0,0,0,0.1);
            background: rgba(255,255,255,0.5);
            color: #1a1a2e;
            font-size: 13px;
            margin-bottom: 10px;
        }
        .edit-form input:focus, .edit-form textarea:focus {
            outline: none;
            border-color: rgba(59,130,246,0.4);
        }
        .edit-form textarea { resize: vertical; min-height: 50px; }
        .edit-form .btn-group { display: flex; gap: 10px; }
        .edit-form .btn-group .btn { flex: 1; text-align: center; margin-top: 0; }
        .back-link { display: block; margin-top: 12px; color: rgba(0,0,0,0.4); font-size: 12px; }
        .messages-container { max-height: 300px; overflow-y: auto; margin-top: 8px; }
        .messages-container::-webkit-scrollbar { width: 4px; }
        .messages-container::-webkit-scrollbar-thumb { background: rgba(0,0,0,0.2); border-radius: 4px; }
    </style>
</head>
<body>
    <div class="glass">
        <img src="${user.avatar || 'https://ui-avatars.com/api/?name=' + encodeURIComponent(user.username) + '&background=3b82f6&color=fff&size=128'}" alt="avatar" class="avatar" />
        <h1>${user.username}</h1>
        <div class="bio">${user.bio || '这个人很懒，什么都没写~'}</div>
        ${user.badge ? `<div class="badge">🏅 ${user.badge}</div>` : ''}
        <div style="text-align:left;margin-top:12px;">
            <div class="field"><span class="field-label">用户名</span><span class="field-value">${user.username}</span></div>
            <div class="field"><span class="field-label">简介</span><span class="field-value">${user.bio || '未设置'}</span></div>
            <div class="field"><span class="field-label">角色</span><span class="field-value">${user.role || '用户'}</span></div>
        </div>

        <!-- ===== 消息分区 ===== -->
        <div style="text-align:left;margin-top:20px;border-top:1px solid rgba(0,0,0,0.08);padding-top:16px;">
            <div class="section-title">📬 消息中心</div>
            <div class="messages-container">
                ${messagesHtml}
            </div>
        </div>

        <!-- ===== 编辑按钮 ===== -->
        <button id="editBtn" class="btn btn-primary" style="margin-top:16px;">✏️ 编辑资料</button>

        <!-- ===== 编辑表单（支持修改用户名和密码） ===== -->
        <div id="editForm" class="edit-form" style="display:none;">
            <form method="POST" action="?username=${username}&action=edit">
                <label>头像 URL</label>
                <input type="text" name="avatar" value="${user.avatar || ''}" placeholder="https://example.com/avatar.png" />
                <label>个人简介</label>
                <textarea name="bio" placeholder="写点什么吧...">${user.bio || ''}</textarea>
                <label>新用户名</label>
                <input type="text" name="newUsername" value="${user.username}" placeholder="新用户名" />
                <label>新密码</label>
                <input type="password" name="newPassword" placeholder="留空则不修改" />
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

// ===== 路由 =====
router
    .post('*/register', (req, env) => handleRegister(req, env))
    .post('*/login', (req, env) => handleLogin(req, env))
    .post('*/logout', (req, env) => handleLogout(req, env))
    .get('*/load-user', (req, env) => handleLoadUser(req, env))
    .put('*/update-profile', (req, env) => handleUpdateProfile(req, env))
    .get('*/get-messages', (req, env) => handleGetMessages(req, env))
    .get('*/account', (req, env) => handleAccount(req, env))
    .all('*', () => new Response('Not Found', { status: 404 }));

export default { ...router };