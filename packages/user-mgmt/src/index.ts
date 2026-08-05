import { AutoRouter, cors } from 'itty-router';
import { getUser } from './utils';
import { Env } from './env';
import { hashPassword } from './auth';

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

// ===== 更新个人资料（独立 API） =====
async function handleUpdateProfile(request: Request, env: Env) {
    try {
        const url = new URL(request.url);
        const username = url.searchParams.get('username');
        if (!username) {
            return new Response(JSON.stringify({ error: 'Missing username' }), { status: 400 });
        }
        const { avatar, bio, newUsername, newPassword } = await request.json();
        
        let updates = [];
        let values = [];
        if (avatar !== undefined) { updates.push('avatar = ?'); values.push(avatar); }
        if (bio !== undefined) { updates.push('bio = ?'); values.push(bio); }
        if (newUsername && newUsername !== username) { updates.push('username = ?'); values.push(newUsername); }
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
            success: true,
            message: 'Profile updated successfully',
            username: newUsername || username
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (e) {
        return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500 });
    }
}

// ===== 个人中心 HTML（漂亮 UI + 完整功能） =====
async function handleAccount(request: Request, env: Env) {
    const url = new URL(request.url);
    const username = url.searchParams.get('username') || 'test123';

    const user = await getUser(env, username);
    if (!user) {
        return new Response('用户不存在', { status: 404 });
    }

    // 查询消息列表
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
            border: none;
        }
        .btn:hover { background: rgba(0,0,0,0.1); }
        .btn-primary { background: rgba(59,130,246,0.15); border-color: rgba(59,130,246,0.2); }
        .btn-primary:hover { background: rgba(59,130,246,0.25); }
        .edit-form { margin-top: 16px; text-align: left; display: none; }
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
        .message { margin-top: 12px; padding: 10px; border-radius: 8px; display: none; }
        .message.success { background: #d4edda; color: #155724; display: block; }
        .message.error { background: #f8d7da; color: #721c24; display: block; }
        .loading { opacity: 0.6; pointer-events: none; }
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

        <div id="message" class="message"></div>

        <button id="editBtn" class="btn btn-primary">✏️ 编辑资料</button>

        <div id="editForm" class="edit-form">
            <label>头像 URL</label>
            <input type="text" id="avatarInput" value="${user.avatar || ''}" placeholder="https://example.com/avatar.png" />
            <label>个人简介</label>
            <textarea id="bioInput" placeholder="写点什么吧...">${user.bio || ''}</textarea>
            <label>新用户名</label>
            <input type="text" id="usernameInput" value="${user.username}" placeholder="新用户名" />
            <label>新密码</label>
            <input type="password" id="passwordInput" placeholder="留空则不修改" />
            <div class="btn-group">
                <button id="saveBtn" class="btn btn-primary">💾 保存</button>
                <button id="cancelBtn" class="btn">取消</button>
            </div>
        </div>

        <a href="?username=${user.username}" class="back-link">🔄 刷新</a>
    </div>

    <script>
        const editBtn = document.getElementById('editBtn');
        const editForm = document.getElementById('editForm');
        const cancelBtn = document.getElementById('cancelBtn');
        const saveBtn = document.getElementById('saveBtn');
        const messageDiv = document.getElementById('message');

        editBtn.addEventListener('click', () => {
            editForm.style.display = 'block';
            editBtn.style.display = 'none';
        });

        cancelBtn.addEventListener('click', () => {
            editForm.style.display = 'none';
            editBtn.style.display = 'inline-block';
            messageDiv.className = 'message';
            messageDiv.textContent = '';
        });

        saveBtn.addEventListener('click', async () => {
            const username = '${username}';
            const avatar = document.getElementById('avatarInput').value.trim();
            const bio = document.getElementById('bioInput').value.trim();
            const newUsername = document.getElementById('usernameInput').value.trim();
            const newPassword = document.getElementById('passwordInput').value.trim();

            saveBtn.classList.add('loading');
            saveBtn.textContent = '保存中...';

            try {
                const resp = await fetch('/update-profile?username=' + username, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ avatar, bio, newUsername, newPassword })
                });
                const data = await resp.json();

                if (data.success) {
                    messageDiv.className = 'message success';
                    messageDiv.textContent = '✅ 保存成功！';
                    setTimeout(() => {
                        window.location.href = '/account?username=' + (data.username || username);
                    }, 1000);
                } else {
                    messageDiv.className = 'message error';
                    messageDiv.textContent = '❌ 保存失败：' + (data.error || '未知错误');
                }
            } catch (e) {
                messageDiv.className = 'message error';
                messageDiv.textContent = '❌ 网络错误，请重试';
            } finally {
                saveBtn.classList.remove('loading');
                saveBtn.textContent = '💾 保存';
            }
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
    .put('/update-profile', (req, env) => handleUpdateProfile(req, env))
    .get('/account', (req, env) => handleAccount(req, env))
    .all('*', () => new Response('Not Found', { status: 404 }));

export default { ...router };