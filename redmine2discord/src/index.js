const encoder = new TextEncoder();

export default {
	async fetch(request, env) {
		if (request.method !== 'POST') {
			return new Response('Method Not Allowed', {
				status: 405,
			});
		}

		const body = await request.text();

		// Redmine Webhook の署名を検証
		if (env.REDMINE_WEBHOOK_SECRET) {
			const signature = request.headers.get('X-Redmine-Signature-256');

			const valid = await verifyRedmineSignature(body, signature, env.REDMINE_WEBHOOK_SECRET);

			if (!valid) {
				return new Response('Invalid signature', {
					status: 401,
				});
			}
		}

		let payload;

		try {
			payload = JSON.parse(body);
		} catch {
			return new Response('Invalid JSON', {
				status: 400,
			});
		}

		const discordPayload = buildDiscordPayload(payload, env.REDMINE_BASE_URL);

		const discordUrl = new URL(env.DISCORD_WEBHOOK_URL);

		// Discord 側で投稿結果を確認できるようにする
		discordUrl.searchParams.set('wait', 'true');

		const response = await fetch(discordUrl, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify(discordPayload),
		});

		if (!response.ok) {
			const message = await response.text();

			console.error(`Discord webhook error: ${response.status} ${message}`);

			return new Response('Discord webhook failed', {
				status: 502,
			});
		}

		return new Response('OK', {
			status: 200,
		});
	},
};

async function verifyRedmineSignature(body, signature, secret) {
	if (!signature || !signature.startsWith('sha256=')) {
		return false;
	}

	const hex = signature.slice('sha256='.length);

	if (!/^[0-9a-f]{64}$/i.test(hex)) {
		return false;
	}

	const signatureBytes = new Uint8Array(hex.match(/.{2}/g).map((value) => Number.parseInt(value, 16)));

	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(secret),
		{
			name: 'HMAC',
			hash: 'SHA-256',
		},
		false,
		['verify'],
	);

	return crypto.subtle.verify('HMAC', key, signatureBytes, encoder.encode(body));
}

function buildDiscordPayload(payload, redmineBaseUrl) {
	const eventType = payload?.type ?? 'unknown';
	const issue = payload?.data?.issue;

	if (!issue) {
		return {
			username: 'Redmine',
			allowed_mentions: {
				parse: [],
			},
			embeds: [
				{
					title: 'Redmine Event',
					description: `\`${eventType}\``,
					timestamp: payload?.timestamp,
				},
			],
		};
	}

	const labels = {
		'issue.created': 'チケット作成',
		'issue.updated': 'チケット更新',
		'issue.deleted': 'チケット削除',
		'issue.closed': 'チケット終了',
	};

	const action = labels[eventType] ?? eventType;

	const baseUrl = redmineBaseUrl.replace(/\/$/, '');

	const issueUrl = `${baseUrl}/issues/${issue.id}`;

	const fields = [];

	if (issue.project?.name) {
		fields.push({
			name: 'プロジェクト',
			value: limit(issue.project.name, 1024),
			inline: true,
		});
	}

	if (issue.tracker?.name) {
		fields.push({
			name: 'トラッカー',
			value: limit(issue.tracker.name, 1024),
			inline: true,
		});
	}

	if (issue.status?.name) {
		fields.push({
			name: 'ステータス',
			value: limit(issue.status.name, 1024),
			inline: true,
		});
	}

	if (issue.priority?.name) {
		fields.push({
			name: '優先度',
			value: limit(issue.priority.name, 1024),
			inline: true,
		});
	}

	if (issue.assigned_to?.name) {
		fields.push({
			name: '担当者',
			value: limit(issue.assigned_to.name, 1024),
			inline: true,
		});
	}

	if (issue.author?.name) {
		fields.push({
			name: '作成者',
			value: limit(issue.author.name, 1024),
			inline: true,
		});
	}

	return {
		username: 'Redmine',

		// Redmine の入力に @everyone などが含まれていても
		// Discord でメンションを発生させない
		allowed_mentions: {
			parse: [],
		},

		embeds: [
			{
				title: limit(`${action}: #${issue.id} ${issue.subject}`, 256),

				url: issueUrl,

				description: issue.description ? limit(issue.description, 2000) : undefined,

				fields,

				timestamp: payload?.timestamp,

				footer: {
					text: 'Redmine',
				},
			},
		],
	};
}

function limit(value, length) {
	const text = String(value ?? '');

	if (text.length <= length) {
		return text;
	}

	return `${text.slice(0, length - 1)}…`;
}
