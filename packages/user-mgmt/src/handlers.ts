import { Env, getForgotPasswordUrl, getRbacEnabled } from './env';
import { getSessionIdFromCookies, checkUserExists, getUser, storeResetToken, storeUser, isTokenExpired, getUserByResetToken, updatePassword, RegistrationData, Credentials } from './utils';
import { hashPassword, comparePassword } from './auth';
import { createSession, deleteSession, loadSession } from './session';
import { sendEmail } from './email';
import { assignDefaultRole, getUserRoles } from './rbac';

export async function handleLoadUser(request: Request, env: Env): Promise<Response> {
    const sessionId = getSessionIdFromCookies(request);
    if (sessionId) {
        const sessionData = await loadSession(env, sessionId);
        if (sessionData) {
            if (getRbacEnabled(env)) {
                try {
                    const user = await getUser(env, sessionData.username);
                    if (user) {
                        const roles = await getUserRoles(env, user.id);
                        sessionData.roles = roles;
                    }
                } catch (error) {
                    console.error('Error fetching user roles:', error);
                }
            }
            return new Response(JSON.stringify(sessionData), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
    return new Response(JSON.stringify({ error: 'User not logged in' }), { status: 401 });
}

export async function handleRegister(request: Request, env: Env): Promise<Response> {
    try {
        const regData = await request.json() as RegistrationData;
        const { username, password } = regData;

        if (!username || !password) {
            return new Response(JSON.stringify({ error: 'Missing required fields' }), { status: 400 });
        }

        const userExists = await checkUserExists(env, username);
        if (userExists) {
            return new Response(JSON.stringify({ error: 'User already exists' }), { status: 409 });
        }

        const hashedPassword = await hashPassword(password);
        const userId = await storeUser(env, { username, hashedPassword });

        if (getRbacEnabled(env)) {
            try {
                await assignDefaultRole(env, userId);
            } catch (error) {
                console.error('Error assigning default role:', error);
            }
        }

        return new Response(JSON.stringify({ message: 'User registered successfully' }), { status: 201 });
    } catch (error) {
        console.error('Error during registration:', error);
        return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500 });
    }
}

export async function handleLogin(request: Request, env: Env): Promise<Response> {
    const credentials = await request.json() as Credentials;
    const { username, password } = credentials;

    try {
        if (!username || !password) {
            return new Response(JSON.stringify({ error: 'Missing username or password' }), { status: 400 });
        }

        const user = await getUser(env, username);
        if (!user) {
            return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401 });
        }

        // 注意：数据库字段是 password（小写）
        const passwordMatch = await comparePassword(password, user.password);
        if (!passwordMatch) {
            return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401 });
        }

        const sessionId = await createSession(env, user);
        return new Response(JSON.stringify({ message: 'Login successful' }), {
            headers: { 'Set-Cookie': `cfw_session=${sessionId}; Secure; Path=/; SameSite=None; Max-Age=${60 * 30}` }
        });
    } catch (error) {
        console.error('Error during login:', error);
        return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500 });
    }
}

export async function handleLogout(request: Request, env: Env): Promise<Response> {
    const sessionId = getSessionIdFromCookies(request);
    if (sessionId) {
        await deleteSession(env, sessionId);
    }
    const headers = new Headers({
        'Set-Cookie': 'cfw_session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
    });
    return new Response(JSON.stringify({ message: 'Logout successful' }), { headers });
}

export async function handleForgotPassword(request: Request, env: Env): Promise<Response> {
    try {
        const { username } = await request.json() as { username: string };
        const user = await getUser(env, username);
        if (!user) {
            return new Response(JSON.stringify({ error: 'User not found' }), { status: 404 });
        }

        const resetToken = crypto.getRandomValues(new Uint8Array(16)).join('');
        await storeResetToken(env, username, resetToken);

        const resetLink = `${getForgotPasswordUrl(env)}?token=${resetToken}`;
        const toEmail = username;
        const toName = user.username; // 直接用 username
        const subject = 'Password Reset Link';
        const contentValue = `Click the following link to reset your password: ${resetLink}`;
        await sendEmail(toEmail, toName, subject, contentValue, env);

        return new Response(JSON.stringify({ message: 'Password reset initiated' }));
    } catch (error) {
        console.error('Error during password reset:', error);
        return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500 });
    }
}

export async function handleForgotPasswordValidate(request: Request, env: Env): Promise<Response> {
    const { token } = await request.json() as { token: string };
    const user = await getUserByResetToken(env, token);
    if (!user) {
        return new Response(JSON.stringify({ error: 'Invalid token' }), { status: 400 });
    }
    const tokenExpired = isTokenExpired(env, user.reset_token_time);
    if (tokenExpired) {
        return new Response(JSON.stringify({ error: 'Token expired' }), { status: 400 });
    }
    return new Response(JSON.stringify({ message: 'Valid Token' }));
}

export async function handleForgotPasswordNewPassword(request: Request, env: Env): Promise<Response> {
    try {
        const { token, password } = await request.json() as { token: string, password: string };
        const user = await getUserByResetToken(env, token);
        if (!user) {
            return new Response(JSON.stringify({ error: 'Invalid token' }), { status: 400 });
        }
        const hashedPassword = await hashPassword(password);
        await updatePassword(env, user.username, hashedPassword);
        return new Response(JSON.stringify({ message: 'Password reset successful' }));
    } catch (error) {
        console.error('Error resetting password:', error);
        return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500 });
    }
}

// Export RBAC handlers
export {
    handleListRoles,
    handleCreateRole,
    handleListPermissions,
    handleGetUserRoles,
    handleAssignRole,
    handleRemoveRole,
    handleGetAuditLogs
} from './handlers/rbac';