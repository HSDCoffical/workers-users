import { Env } from './env';

export function getSessionIdFromCookies(request: Request): string | null {
    const cookieHeader = request.headers.get('Cookie');
    if (cookieHeader) {
        const cookies = cookieHeader.split(';').map(cookie => cookie.trim());
        const sessionCookie = cookies.find(cookie => cookie.startsWith('cfw_session='));
        if (sessionCookie) {
            return sessionCookie.split('=')[1];
        }
    }
    return null;
}

export async function checkUserExists(env: Env, username: string): Promise<boolean> {
    const checkUserQuery = 'SELECT username FROM users WHERE username = ?';
    const checkUserStmt = await env.usersDB.prepare(checkUserQuery);
    const existingUser = await checkUserStmt.bind(username).all();
    return existingUser.success && existingUser.results.length > 0;
}

export async function storeUser(env: Env, user: { username: string, hashedPassword: string }): Promise<number> {
    const insertUserQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';
    const insertUserStmt = await env.usersDB.prepare(insertUserQuery);
    const result = await insertUserStmt.bind(user.username, user.hashedPassword).run();
    
    if (!result.success || !result.meta.last_row_id) {
        throw new Error('Failed to create user');
    }
    
    return Number(result.meta.last_row_id);
}

export async function getUser(env: Env, username: string): Promise<any> {
    const query = 'SELECT * FROM users WHERE username = ?1';
    const result = (await env.usersDB.prepare(query).bind(username).all()).results;
    return result.length > 0 ? result[0] : null;
}

export async function storeResetToken(env: Env, username: string, resetToken: string): Promise<void> {
    const updateQuery = 'UPDATE users SET reset_token = ?, reset_token_time = ? WHERE username = ?';
    await env.usersDB.prepare(updateQuery).bind(resetToken, Date.now(), username).run();
}

export async function getUserByResetToken(env: Env, token: string): Promise<any> {
    const query = 'SELECT * FROM users WHERE reset_token = ?';
    const result = (await env.usersDB.prepare(query).bind(token).all()).results;
    return result.length > 0 ? result[0] : null;
}

export async function updatePassword(env: Env, username: string, hashedPassword: string): Promise<void> {
    const updateQuery = 'UPDATE users SET password = ?, reset_token = NULL, reset_token_time = NULL WHERE username = ?';
    await env.usersDB.prepare(updateQuery).bind(hashedPassword, username).run();
}

export function isTokenExpired(env: Env, tokenTime: number): boolean {
    const millisecondsInMinute = 1000 * 60;
    const tokenExpirationTime = env.TOKEN_VALID_MINUTES * millisecondsInMinute;
    return Date.now() - tokenTime > tokenExpirationTime;
}

export interface Credentials {
    username: string;
    password: string;
}

export interface RegistrationData extends Credentials {}