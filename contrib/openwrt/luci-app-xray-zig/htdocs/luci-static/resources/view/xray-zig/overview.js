'use strict';
'require poll';
'require rpc';
'require view';

const callSnapshot = rpc.declare({
	object: 'luci.xray-zig',
	method: 'snapshot',
	expect: {}
});

const history = [];
let previousSample = null;

function text(value) {
	return document.createTextNode(String(value == null ? '—' : value));
}

function parseMetrics(source) {
	const metrics = [];
	(source || '').split('\n').forEach(function(line) {
		if (!line || line.charAt(0) === '#')
			return;

		const match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+0-9.eE]+)$/);
		if (!match)
			return;

		const labels = {};
		const labelPattern = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"])*)"/g;
		let label;
		while ((label = labelPattern.exec(match[2] || '')) !== null)
			labels[label[1]] = label[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\');

		metrics.push({ name: match[1], labels: labels, value: Number(match[3]) });
	});
	return metrics;
}

function matches(entry, labels) {
	for (const key in labels)
		if (entry.labels[key] !== labels[key])
			return false;
	return true;
}

function metric(metrics, name, labels) {
	const found = metrics.find(function(entry) {
		return entry.name === name && matches(entry, labels || {});
	});
	return found ? found.value : 0;
}

function select(metrics, name, labels) {
	return metrics.filter(function(entry) {
		return entry.name === name && matches(entry, labels || {});
	});
}

function sum(metrics, name, labels) {
	return select(metrics, name, labels).reduce(function(total, entry) {
		return total + entry.value;
	}, 0);
}

function formatNumber(value) {
	return Number(value || 0).toLocaleString();
}

function formatBytes(value) {
	let bytes = Number(value || 0);
	const units = [ 'B', 'KiB', 'MiB', 'GiB', 'TiB' ];
	let unit = 0;
	while (bytes >= 1024 && unit < units.length - 1) {
		bytes /= 1024;
		unit++;
	}
	return (unit ? bytes.toFixed(bytes >= 100 ? 0 : 1) : bytes.toFixed(0)) + ' ' + units[unit];
}

function formatDuration(seconds) {
	seconds = Math.max(0, Number(seconds || 0));
	const days = Math.floor(seconds / 86400);
	const hours = Math.floor((seconds % 86400) / 3600);
	const minutes = Math.floor((seconds % 3600) / 60);
	if (days)
		return days + 'd ' + hours + 'h';
	if (hours)
		return hours + 'h ' + minutes + 'm';
	return minutes + 'm ' + Math.floor(seconds % 60) + 's';
}

function badge(label, good) {
	return E('span', { 'class': 'xz-badge ' + (good ? 'xz-good' : 'xz-bad') }, [ text(label) ]);
}

function card(title, value, detail, state) {
	return E('div', { 'class': 'xz-card' + (state ? ' xz-' + state : '') }, [
		E('div', { 'class': 'xz-card-title' }, [ text(title) ]),
		E('div', { 'class': 'xz-card-value' }, [ text(value) ]),
		E('div', { 'class': 'xz-card-detail' }, [ text(detail || '') ])
	]);
}

function capacity(label, value, limit) {
	const ratio = limit > 0 ? Math.min(100, value * 100 / limit) : 0;
	return E('div', { 'class': 'xz-capacity' }, [
		E('div', { 'class': 'xz-capacity-label' }, [
			E('span', {}, [ text(label) ]),
			E('span', {}, [ text(formatNumber(value) + ' / ' + formatNumber(limit)) ])
		]),
		E('div', { 'class': 'xz-meter' }, [
			E('span', { 'style': 'width:' + ratio.toFixed(1) + '%' })
		])
	]);
}

function table(headers, rows) {
	return E('div', { 'class': 'table xz-table' }, [
		E('div', { 'class': 'tr table-titles' }, headers.map(function(header) {
			return E('div', { 'class': 'th' }, [ text(header) ]);
		})),
		...rows.map(function(row) {
			return E('div', { 'class': 'tr' }, row.map(function(value) {
				return E('div', { 'class': 'td' }, [ text(value) ]);
			}));
		})
	]);
}

function section(title, subtitle, content) {
	return E('section', { 'class': 'cbi-section xz-section' }, [
		E('div', { 'class': 'xz-section-heading' }, [
			E('h3', {}, [ text(title) ]),
			E('p', {}, [ text(subtitle) ])
		]),
		content
	]);
}

function sparkline(samples, key, color) {
	const values = samples.map(function(sample) { return sample[key] || 0; });
	const maxValue = Math.max(1, ...values);
	const width = 600;
	const height = 96;
	const points = values.map(function(value, index) {
		const x = values.length > 1 ? index * width / (values.length - 1) : width;
		const y = height - (value / maxValue * (height - 8)) - 4;
		return x.toFixed(1) + ',' + y.toFixed(1);
	}).join(' ');
	return E('svg', { 'class': 'xz-spark', 'viewBox': '0 0 600 96', 'preserveAspectRatio': 'none' }, [
		E('polyline', { 'points': points, 'fill': 'none', 'stroke': color, 'stroke-width': '3' })
	]);
}

function updateHistory(metrics) {
	const now = Date.now();
	const uplink = sum(metrics, 'xray_zig_bytes_total', { direction: 'uplink' }) +
		sum(metrics, 'xray_zig_bpf_sockhash_bytes_total', { direction: 'uplink' });
	const downlink = sum(metrics, 'xray_zig_bytes_total', { direction: 'downlink' }) +
		sum(metrics, 'xray_zig_bpf_sockhash_bytes_total', { direction: 'downlink' });
	let sample = { uplink: 0, downlink: 0 };

	if (previousSample && now > previousSample.time) {
		const elapsed = (now - previousSample.time) / 1000;
		sample.uplink = Math.max(0, (uplink - previousSample.uplink) / elapsed);
		sample.downlink = Math.max(0, (downlink - previousSample.downlink) / elapsed);
	}

	previousSample = { time: now, uplink: uplink, downlink: downlink };
	history.push(sample);
	while (history.length > 60)
		history.shift();
	return sample;
}

function renderDashboard(snapshot) {
	const status = snapshot.status || {};
	const bpf = snapshot.bpf || {};
	const metrics = parseMetrics(snapshot.metrics);
	const current = updateHistory(metrics);
	const active = status.capacity || {};
	const listeners = status.listeners || {};
	const successes = metric(metrics, 'xray_zig_connections_total', { inbound: 'all', outbound: 'all', result: 'success' });
	const errors = metric(metrics, 'xray_zig_connections_total', { inbound: 'all', outbound: 'all', result: 'error' });
	const dnsActive = metric(metrics, 'xray_zig_dns_queries_active');
	const dnsLimit = metric(metrics, 'xray_zig_dns_query_limit');
	const rawActive = metric(metrics, 'xray_zig_raw_reactor_connections');
	const rawLimit = metric(metrics, 'xray_zig_raw_reactor_limit');
	const offloaded = sum(metrics, 'xray_zig_bpf_offloaded_flows', { network: 'tcp' });

	const routingRows = select(metrics, 'xray_zig_routing_decisions_total', { result: 'selected' })
		.map(function(entry) { return [ entry.labels.outbound, entry.labels.rule, formatNumber(entry.value) ]; });
	const dnsRows = select(metrics, 'xray_zig_dns_queries_total', { resolver: 'all' })
		.map(function(entry) { return [ entry.labels.qtype, entry.labels.result, formatNumber(entry.value) ]; });
	const realityRows = select(metrics, 'xray_zig_reality_handshakes_total')
		.map(function(entry) { return [ entry.labels.stage, entry.labels.result, formatNumber(entry.value) ]; });
	const offloadRows = select(metrics, 'xray_zig_bpf_offload_total', { network: 'tcp' })
		.filter(function(entry) { return entry.value > 0 || entry.labels.result === 'offloaded'; })
		.map(function(entry) { return [ entry.labels.owner, entry.labels.result, formatNumber(entry.value) ]; });
	const mapRows = select(metrics, 'xray_zig_bpf_map_capacity').map(function(entry) {
		return [
			entry.labels.map,
			formatNumber(metric(metrics, 'xray_zig_bpf_map_entries', { map: entry.labels.map })),
			formatNumber(entry.value)
		];
	});
	const events = (snapshot.events || []).slice().reverse();

	return E('div', { 'class': 'xz-dashboard' }, [
		E('div', { 'class': 'xz-hero' }, [
			E('div', {}, [
				E('h2', {}, [ text('xray-zig') ]),
				E('p', {}, [ text('Live protocol, runtime and eBPF observability') ])
			]),
			E('div', { 'class': 'xz-health' }, [
				badge(status.ready ? 'Ready' : 'Not ready', !!status.ready),
				badge('Control API', !snapshot.error)
			])
		]),
		E('div', { 'class': 'xz-card-grid' }, [
			card('Version', status.version || 'unknown', status.dataplane || 'unknown'),
			card('Uptime', formatDuration(status.uptime_seconds), 'runtime'),
			card('Connections', formatNumber(successes), formatNumber(errors) + ' errors', errors ? 'warn' : 'good'),
			card('SOCKHASH', formatNumber(offloaded), 'active flows', bpf.sockhash_monitor ? 'good' : 'warn'),
			card('Uplink', formatBytes(current.uplink) + '/s', 'live browser rate'),
			card('Downlink', formatBytes(current.downlink) + '/s', 'live browser rate')
		]),
		section('Capacity', 'Current occupancy against bounded runtime limits', E('div', { 'class': 'xz-capacity-grid' }, [
			capacity('Listeners', listeners.active || 0, listeners.expected || 0),
			capacity('Raw reactor', rawActive, rawLimit),
			capacity('DNS concurrency', dnsActive, dnsLimit),
			capacity('SOCKHASH flows', bpf.offloaded_flows || 0, bpf.flow_capacity || 0)
		])),
		section('Traffic', 'Recent browser-memory rate; no time-series database runs on the router', E('div', { 'class': 'xz-chart-grid' }, [
			E('div', { 'class': 'xz-chart' }, [ E('strong', {}, [ text('Uplink') ]), sparkline(history, 'uplink', '#34d399') ]),
			E('div', { 'class': 'xz-chart' }, [ E('strong', {}, [ text('Downlink') ]), sparkline(history, 'downlink', '#60a5fa') ])
		])),
		section('Routing', 'Bounded outbound tags and ordered rule outcomes', table([ 'Outbound', 'Rule', 'Decisions' ], routingRows)),
		section('DNS & FakeDNS', 'Query outcomes and current pool state', E('div', { 'class': 'xz-split' }, [
			table([ 'Query type', 'Result', 'Total' ], dnsRows),
			table([ 'Family', 'Active leases', 'Capacity' ], [
				[ 'IPv4', formatNumber(metric(metrics, 'xray_zig_fakedns_leases', { family: 'ipv4', state: 'active' })), formatNumber(metric(metrics, 'xray_zig_fakedns_pool_capacity', { family: 'ipv4' })) ],
				[ 'IPv6', formatNumber(metric(metrics, 'xray_zig_fakedns_leases', { family: 'ipv6', state: 'active' })), formatNumber(metric(metrics, 'xray_zig_fakedns_pool_capacity', { family: 'ipv6' })) ]
			])
		])),
		section('REALITY & Vision', 'Failure stages remain separate from Vision eligibility and offload admission', E('div', { 'class': 'xz-split' }, [
			table([ 'REALITY stage', 'Result', 'Total' ], realityRows),
			table([ 'Transition', 'Success', 'Error' ], [
				[ 'CommandDirect', formatNumber(metric(metrics, 'xray_zig_vision_transitions_total', { transition: 'command_direct', result: 'success' })), formatNumber(metric(metrics, 'xray_zig_vision_transitions_total', { transition: 'command_direct', result: 'error' })) ],
				[ 'Raw handoff', formatNumber(metric(metrics, 'xray_zig_vision_transitions_total', { transition: 'raw_handoff', result: 'success' })), formatNumber(metric(metrics, 'xray_zig_vision_transitions_total', { transition: 'raw_handoff', result: 'error' })) ],
				[ 'SOCKHASH handoff', formatNumber(metric(metrics, 'xray_zig_vision_transitions_total', { transition: 'sockhash_handoff', result: 'success' })), formatNumber(metric(metrics, 'xray_zig_vision_transitions_total', { transition: 'sockhash_handoff', result: 'error' })) ]
			])
		])),
		section('eBPF', 'Owned program state, bounded maps and admission results', E('div', {}, [
			E('div', { 'class': 'xz-hook-row' }, [
				badge('SK_LOOKUP', !!bpf.sk_lookup),
				badge('Parser', !!bpf.sockhash_parser),
				badge('Verdict', !!bpf.sockhash_verdict),
				badge('Monitor', !!bpf.sockhash_monitor),
				badge('FakeDNS pins', !!bpf.fakedns_pin_compatible)
			]),
			E('div', { 'class': 'xz-split' }, [
				table([ 'Owner', 'Admission result', 'Total' ], offloadRows),
				table([ 'Map', 'Entries', 'Capacity' ], mapRows)
			]),
			E('p', { 'class': 'xz-note' }, [ text('SOCKHASH byte divergence: ' + formatBytes(bpf.byte_divergence || 0) + '; redirect errors: ' + formatNumber(metric(metrics, 'xray_zig_bpf_sockhash_redirect_errors_total', { network: 'tcp' }))) ])
		])),
		section('Recent events', 'Bounded, low-rate lifecycle events; newest first', table([ 'Sequence', 'Kind', 'Detail' ], events.map(function(event) {
			return [ event.sequence, event.kind, event.detail ];
		})))
	]);
}

return view.extend({
	load: function() {
		return callSnapshot();
	},

	render: function(snapshot) {
		if (!document.getElementById('xz-dashboard-style'))
			document.head.appendChild(E('link', {
				'id': 'xz-dashboard-style',
				'rel': 'stylesheet',
				'href': L.resource('xray-zig/dashboard.css')
			}));

		const root = E('div', { 'id': 'xz-dashboard-root' }, [ renderDashboard(snapshot || {}) ]);
		poll.add(function() {
			return callSnapshot().then(function(next) {
				root.replaceChildren(renderDashboard(next || {}));
			});
		}, 15);
		return root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
