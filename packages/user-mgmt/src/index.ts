/**
 * This module defines a Cloudflare Worker for managing user authentication and session management in a serverless
 * architecture. It utilizes Cloudflare's D1 Database to persist user information and integrates with a custom
 * session management service for maintaining user sessions. The worker offers endpoints for user registration,
 * authentication (login), session termination (logout), password reset functionalities, and retrieving user
 * session information, catering to the foundational needs of secure and stateful web applications.
 *
 * Utilizing SHA-256 for password hashing, this worker prioritizes security while acknowledging the operational
 * constraints of Cloudflare Workers, such as the impracticality of employing bcrypt for hashing due to its
 * computational intensity. Additionally, the worker implements essential Cross-Origin Resource Sharing (CORS)
 * handling capabilities to ensure seamless interaction with web clients across different origins.
 *
 * By defining a structured `Env` interface, the worker enforces type checking on environment variables,
 * guaranteeing the availability of external resources like the user database (usersDB) and session management
 * services. This approach enhances the reliability and maintainability of the worker in handling user
 * authentication and session management tasks.
 *
 * Features:
 * - Registration: Validates user data and stores it securely in the database.
 * - Login: Authenticates users by validating credentials and initiating a session.
 * - Logout: Terminates an active user session and clears related data.
 * - Password Reset: Facilitates password recovery processes for users.
 * - Session Data Retrieval: Demonstrates real-time session management by fetching session data.
 * - CORS Handling: Manages CORS preflight requests to support diverse web clients.
 *
 * This worker is architected to serve as a secure, scalable foundation for building web applications on the
 * Cloudflare platform, showcasing the feasibility of leveraging serverless architectures for complex
 * application functionalities such as user management and session control.
 */
import { AutoRouter, cors, IRequest } from 'itty-router';
// Defines the environment variables required by the worker.
import { Env, getRbacEnabled } from './env';
import { bootstrapSuperAdmin } from './rbac/bootstrap';

import {
	handleRegister,
	handleLogin,
	handleLogout,
	handleForgotPassword,
	handleForgotPasswordValidate,
	handleForgotPasswordNewPassword,
	handleLoadUser,
	handleListRoles,
	handleCreateRole,
	handleListPermissions,
	handleGetUserRoles,
	handleAssignRole,
	handleRemoveRole,
	handleGetAuditLogs,
} from './handlers';

// 导入必要的工具函数
import { getSessionIdFromCookies, getUser } from './utils';
import { loadSession } from './session';

// ========== CORS 配置：允许所有来源（兼容任意前端域名） ==========
const { preflight, corsify } = cors({
	origin: true,
	credentials: true,
	allowMethods: ['GET', 'POST', 'PUT', 'DELETE'],
	maxAge: 84600,
});
// ==============================================================

// Flag to ensure bootstrap only runs once per worker instance
let bootstrapCompleted = false;

/**
 * Middleware to run bootstrap on first request.
 *
 * RACE CONDITION NOTE: In a high-concurrency scenario with multiple simultaneous
 * requests during worker startup, there is a small race window where multiple
 * requests could pass the `!bootstrapCompleted` check before the flag is set.
 * This is acceptable because:
 * 1. The flag is set immediately after the check to minimize the window
 * 2. The underlying database operations are idempotent (INSERT OR IGNORE)
 * 3. A proper lock would add significant complexity without material benefit
 *
 * Uses ctx.waitUntil() for non-blocking execution so bootstrap doesn't delay requests.
 */
function bootstrapMiddleware(request: IRequest, env: Env, ctx: ExecutionContext) {
	if (!bootstrapCompleted && getRbacEnabled(env)) {
		bootstrapCompleted = true; // Set immediately to minimize race window
		ctx.waitUntil(
			bootstrapSuperAdmin(env).catch(error => {
				console.error('Error during RBAC bootstrap:', error);
				// Continue processing even if bootstrap fails
			})
		);
	}
}

const router = AutoRouter<IRequest, [Env, ExecutionContext]>({
	before: [preflight, bootstrapMiddleware],  // add preflight and bootstrap upstream
	finally: [corsify],   // and corsify downstream
});

// ===== 直接在路由文件中定义更新资料函数（避免导出冲突） =====
async function updateProfile(request: Request, env: Env): Promise<Response> {
    let sessionId = getSessionIdFromCookies(request);
    if (!sessionId) {
        const url = new URL(request.url);
        sessionId = url.searchParams.get('sessionId') || '';
    }
    if (!sessionId) {
        return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
    }

    const sessionData = await loadSession(env, sessionId);
    if (!sessionData || !sessionData.username) {
        return new Response(JSON.stringify({ error: 'Invalid session' }), { status: 401 });
    }

    try {
        const { avatar, bio } = await request.json() as { avatar?: string, bio?: string };

        if (avatar === undefined && bio === undefined) {
            return new Response(JSON.stringify({ error: 'No fields to update' }), { status: 400 });
        }

        const updates: string[] = [];
        const values: any[] = [];
        if (avatar !== undefined) { updates.push('avatar = ?'); values.push(avatar); }
        if (bio !== undefined) { updates.push('bio = ?'); values.push(bio); }

        values.push(sessionData.username);
        const query = `UPDATE users SET ${updates.join(', ')} WHERE username = ?`;
        await env.usersDB.prepare(query).bind(...values).run();

        return new Response(JSON.stringify({ message: 'Profile updated successfully' }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        console.error('Error updating profile:', error);
        return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500 });
    }
}
// ==========================================================

// Define routes
router
	.post('*/register', (request, env, ctx) => handleRegister(request, env))
	.post('*/login', (request, env, ctx) => handleLogin(request, env))
	.post('*/logout', (request, env, ctx) => handleLogout(request, env))
	.post('*/forgot-password', (request, env, ctx) => handleForgotPassword(request, env))
	.post('*/forgot-password-validate', (request, env, ctx) => handleForgotPasswordValidate(request, env))
	.post('*/forgot-password-new-password', (request, env, ctx) => handleForgotPasswordNewPassword(request, env))
	.get('*/load-user', (request, env, ctx) => handleLoadUser(request, env))
	.put('*/update-profile', (request, env, ctx) => updateProfile(request, env)); // 使用内联函数

// Middleware to check if RBAC is enabled
function requireRbacEnabled(request: IRequest, env: Env): Response | void {
	if (!getRbacEnabled(env)) {
		return new Response(JSON.stringify({ error: 'RBAC is not enabled' }), {
			status: 403,
			headers: { 'Content-Type': 'application/json' }
		});
	}
}

// RBAC routes - all require RBAC to be enabled
router
	.get('*/rbac/roles', requireRbacEnabled, (request, env) => handleListRoles(request, env))
	.post('*/rbac/roles', requireRbacEnabled, (request, env) => handleCreateRole(request, env))
	.get('*/rbac/permissions', requireRbacEnabled, (request, env) => handleListPermissions(request, env))
	.get('*/rbac/users/:userId/roles', requireRbacEnabled, (request, env) => handleGetUserRoles(request, env))
	.post('*/rbac/users/:userId/roles', requireRbacEnabled, (request, env) => handleAssignRole(request, env))
	.delete('*/rbac/users/:userId/roles/:roleId', requireRbacEnabled, (request, env) => handleRemoveRole(request, env))
	.get('*/rbac/audit-logs', requireRbacEnabled, (request, env) => handleGetAuditLogs(request, env))
	.all('*', () => new Response('Not Found', { status: 404 }));

export default { ...router }; // Export the router
