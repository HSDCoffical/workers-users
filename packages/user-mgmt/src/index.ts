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
            return new Response(JSON.stringify({ error: 'User data corrupted' }), { status: 500 });
        }
        const match = await comparePassword(password, storedPassword);
        if (!match) {
            return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401 });
        }
        return new Response(JSON.stringify({ message: 'Login successful', username: user.username }), {
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

// ===== 4. 更新个人资料 =====
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

// ===== 7. 个人中心 HTML（背景图使用你的 GitHub 图片） =====
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
            if (newUsername && newUsername !== username) { updates.push('username = ?'); values.push(newUsername); }
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
            return new Response(null, {
                status: 302,
                headers: { 'Location': `/account?username=${newUsername || username}` }
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

    // 使用你的 GitHub 图片，加时间戳强制刷新
    const bgImage = 'https://raw.githubusercontent.com/HSDCofficial/users-manage-react/main/public/bg.jpg?' + Date.now();

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
        .section-title { font-size: 16px; font-weight: 600; margin: