import show from '../static/show.html';

interface AppData {
	client_id: string;
	client_secret: string;
	id: string;
}

interface StoredAppData {
	clientId: string;
	clientSecret: string;
}

interface NewAppResponse {
	login_link: string;
}

interface ErrorResponse {
	error: string;
}

interface Env {
	KV: KVNamespace;
	INSTANCE: string;
}

const getCookie = (cookieString, key) => {
	if (cookieString) {
		const allCookies = cookieString.split("; ")
		const targetCookie = allCookies.find(cookie => cookie.includes(key))
		if (targetCookie) {
			const [_, value] = targetCookie.split("=")
			return value
		}
	}

	return null
}

const createHash = async (input: string): Promise<string> => {
	const encoder = new TextEncoder();
	const data = encoder.encode(input);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
};

const verifyAuth = async (request, env): Promise<boolean> => {
	try {
		const session = getCookie(request.headers.get("cookie"), 'authentication');
		if (!session) {
			throw new Error('Authentication required');
		}
		const userToken = await env.KV.get(`session:${session}`);
		if (!userToken) {
			throw new Error('Authentication required');
		}
		return true;
	} catch (error) {
		console.error('Error in verifyAuth:', error);
		return false;
	}
};

const verifySession = async (request, env): Promise<Response> => {
	const isAuthenticated = await verifyAuth(request, env);
	if (!isAuthenticated) {
		const redirectUrl = new URL(request.url);
		redirectUrl.pathname = "/auth";
		const loginLink = `${env.INSTANCE}/oauth/authorize?client_id=${env.APP_CLIENT_ID}&redirect_uri=${encodeURIComponent(redirectUrl.toString())}&response_type=code&scope=read`;
		return new Response(loginLink, { status: 401 });
	}
	return new Response(JSON.stringify({}), { status: 200, headers: { 'Content-Type': 'application/json' } });
};

const newSession = async (request, env): Promise<Response> => {
	try {
		const { searchParams } = new URL(request.url)
		let code = searchParams.get('code')

		const redirectUrl = URL.parse(request.url);
		redirectUrl.pathname = "/auth";
		redirectUrl.searchParams.delete('code');
		const tokenRes = await fetch(`${env.INSTANCE}/oauth/token`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'User-Agent': 'Botsinbox-Tokens'
			},
			body: JSON.stringify({
				client_id: env.APP_CLIENT_ID,
				client_secret: env.APP_CLIENT_SECRET,
				redirect_uri: redirectUrl?.toString(),
				code: code,
				grant_type: 'authorization_code'
			})
		});

		if (!tokenRes.ok) {
			throw new Error(`Failed to get token: ${await tokenRes.text()}`);
		}
		const tokenData =  await tokenRes.json<{ access_token: string }>();
		const session = crypto.randomUUID()
		await env.KV.put(`session:${session}`, tokenData.access_token, { expirationTtl: 60*60*24*7 /* Valid for 7 days */ });
		return new Response(null, { status: 302, headers: { "Set-Cookie": `authentication=${session}; HttpOnly`, "Location": "/" } });
	} catch (error) {
		console.error('Error in verifyAccount:', error);
		const response: ErrorResponse = { error: error.message };
		return new Response(JSON.stringify(response), { status: 500, headers: { 'Content-Type': 'application/json' } });
	}
}

const handleNewApp = async (request, env): Promise<Response> => {
	if (!await verifyAuth(request, env)) {
		const response: ErrorResponse = { error: "not authenticated" };
		return new Response(JSON.stringify(response), { status: 401, headers: { 'Content-Type': 'application/json' } });
	}

	try {
		const body = await request.json<{ app_name: string }>();
		const appName = body.app_name;

		if (!appName) {
			throw new Error('Application name is required');
		}
		// Build the login link
		const redirectUrl = URL.parse(request.url);
		redirectUrl.pathname = "/continue";

		const appRes = await fetch(`${env.INSTANCE}/api/v1/apps`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'User-Agent': 'Botsinbox-Tokens'
			},
			body: JSON.stringify({
				client_name: appName,
				redirect_uris: redirectUrl?.toString(),
				scopes: 'read write'
			})
		});

		if (!appRes.ok) {
			throw new Error(`Failed to create app: ${await appRes.text()}`);
		}

		const appData: AppData = await appRes.json();
		const clientId = appData.client_id;
		const clientSecret = appData.client_secret;
		const appId = appData.id;

		// Store client_id and client_secret in Workers KV
		const timestamp = Date.now();
		const hashKey = await createHash(`${timestamp}-${appId}`);
		await env.KV.put(`app:${hashKey}`, JSON.stringify({ clientId, clientSecret, appName }), { expirationTtl: 60 * 60 /* One hour TTL */ });

		const login_link = `${env.INSTANCE}/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUrl?.toString()}&response_type=code&scope=read+write&state=${hashKey}`;

		const response: NewAppResponse = { login_link };
		return new Response(JSON.stringify(response), { status: 200, headers: { 'Content-Type': 'application/json' } });

	} catch (error) {
		console.error('Error in handleNewApp:', error);
		const response: ErrorResponse = { error: error.message };
		return new Response(JSON.stringify(response), { status: 500, headers: { 'Content-Type': 'application/json' } });
	}
};

const handleContinue = async (request, env): Promise<Response> => {
	try {
		const { searchParams } = new URL(request.url);
		const code = searchParams.get('code');
		const hashKey = searchParams.get('state');

		if (!hashKey || !code) {
			throw new Error('Hash and code are required');
		}

		// Retrieve client_id and client_secret from KV
		const storedData = await env.KV.get(`app:${hashKey}`);
		if (!storedData) {
			throw new Error('Hash not found in KV');
		}

		const { clientId, clientSecret }: StoredAppData = JSON.parse(storedData);

		// Construct the redirect URL without code and state
		const redirectUrl = new URL(request.url);
		redirectUrl.pathname = "/continue";
		redirectUrl.searchParams.delete('code');
		redirectUrl.searchParams.delete('state');

		// Request access token
		const tokenRes = await fetch(`${env.INSTANCE}/oauth/token`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'User-Agent': 'Botsinbox-Tokens'
			},
			body: JSON.stringify({
				client_id: clientId,
				client_secret: clientSecret,
				redirect_uri: redirectUrl.toString(),
				code: code,
				grant_type: 'authorization_code',
			})
		});

		if (!tokenRes.ok) {
			const resJson = await tokenRes.json();
			if (resJson.error === "sql: no rows in result set") {
				redirectUrl.pathname = "";
				return Response.redirect(redirectUrl, 302);
			}
			throw new Error(`Failed to get token: ${await tokenRes.text()}`);
		}

		const tokenData = await tokenRes.json<{ access_token: string }>();
		const accessToken = tokenData.access_token;

		// Transform HTML to include the access token
		return new HTMLRewriter()
			.on("#token", {
				element(element) {
					element.setAttribute('value', accessToken);
				},
			})
			.transform(new Response(show, { headers: { "Content-Type": "text/html" } }));
	} catch (error) {
		console.error('Error in handleContinue:', error);
		const response = { error: error.message };
		return new Response(JSON.stringify(response), { status: 500, headers: { 'Content-Type': 'application/json' } });
	}
};

export default {
	async fetch(request: Request, env: Env, ctx: EventContext<any, any, any>): Promise<Response> {
		const url = URL.parse(request.url);
		// @ts-ignore
		switch (url.pathname) {
			case '/new-app':
				return await handleNewApp(request, env);
			case '/continue':
				return await handleContinue(request, env);
			case '/auth':
				return await newSession(request, env);
			case '/session':
				return await verifySession(request, env);
			default:
				return new Response('Not Found', { status: 404 });
		}
	}
};
