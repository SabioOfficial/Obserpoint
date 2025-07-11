async function fetchJSON(url, options) {
	const res = await fetch(url, options || {});
	if (!res.ok) {
		throw new Error(`HTTP error! status: ${res.status}`);
	}
	return await res.json();
}

function computeUptime(checks) {
	if (!checks.length) return 'N/A';
	const upCount = checks.filter(c => c.up).length;
	return ((upCount / checks.length) * 100).toFixed(2);
}

function getUptimeColor(uptime) {
	if (uptime === 'N/A') return 'neutral-1';
	const val = parseFloat(uptime);
	if (val >= 99.9) return 'success';
	if (val >= 99) return 'warning';
	return 'danger';
}

function getResponseColor(response) {
	if (response === '--' || response === null) return 'neutral-1';
	const val = parseInt(response);
	if (val <= 200) return 'success';
	if (val <= 1000) return 'warning';
	return 'danger';
}

function getStatusColor(status) {
	if (status === 'up') return 'success';
	else if (status === 'down') return 'danger';
	else if (status === 'pending') return 'neutral-1';
}

function renderStatusCard(target, checks) {
	const container = document.getElementById('live-api-target__div');
	const latest = checks[0] || {};
	const uptime = computeUptime(checks);
	const validResponses = checks
		.map(c => c.responseTimeMs)
		.filter(tm => typeof tm === 'number');
	const avgResponseTime = validResponses.length
		? Math.round(
				validResponses.reduce((sum, tm) => sum + tm, 0) / validResponses.length
			)
		: null;
	const response = avgResponseTime != null
		? `${avgResponseTime}ms`
		: '--';
	const status = target.status;
	const signalImg =
		status === 'up' ? 'up.png' :
		status === 'down' ? 'down.png' :
		status === 'pending' ? 'pending.png' :
		'warning.png';
	const statusColor = getStatusColor(status);
	const uptimeColor = getUptimeColor(uptime);
	const responseColor = getResponseColor(response);
	const div = document.createElement('div');
	div.className = `item__div status-${status}`;
	div.innerHTML = `
		<div class="demo-info__div">
			<img class="demo-embed__favicon" height="27" width="27"/>
			<h3 class="demo-embed__name">${target.name}</h3>
		</div>
        <p>
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
            </svg>
            <a href="${target.url}" style="color: var(--info);" target="_blank">${target.url}</a>
        </p>
        <p>
            <img src="icons/signals/${signalImg}" width="16" height="16" />
            <span style="color: var(--${statusColor}); font-weight: bold;">
                ${status.toUpperCase()}
                ${latest.statusCode != null ? `(${latest.statusCode})` : ''}
            </span>
        </p>
        <p>
            Uptime 
            <span style="color: var(--${uptimeColor});">${uptime}%</span>
            <span title="An uptime of over 99.9% is recommended for businesses whilst an uptime of over 99% is fine for casual projects." class="help__btn">?</span>
        </p>
        <p>
			Response Time 
			<span style="color: var(--${responseColor});">${response}</span>
			<span title="A response time of less than 200ms is recommended for businesses whilst a response time of less than 1,000ms is fine for casual projects." class="help__btn">?</span>
		</p>
    `;
	container.appendChild(div);

	let faviconUrl, fallbackFavicon;
	try {
		const host = new URL(target.url).hostname;
		faviconUrl = `https://www.google.com/s2/favicons?domain=${host}&sz=64`;
	} catch {
		fallbackFavicon = new URL('/favicon.ico', target.url).href;
	}
	if (!faviconUrl) {
		fallbackFavicon = fallbackFavicon || new URL('/favicon.ico', target.url).href;
	}

	const img = div.querySelector('.demo-embed__favicon');
	if (faviconUrl) {
		img.src = faviconUrl;
		img.onerror = () => {
			if (fallbackFavicon) img.src = fallbackFavicon;
		};
	} else if (fallbackFavicon) {
		img.src = fallbackFavicon;
	}
}

let liveIndex = 0;
let liveCycleInterval;

function startLiveCycle() {
	const liveItems = document.querySelectorAll('#live-api-target__div .item__div');
	if (liveCycleInterval) clearInterval(liveCycleInterval);
	if (liveItems.length === 0) return;
	liveIndex = 0;

	function cycleLiveHighlight() {
		liveItems.forEach((el, i) => {
			el.classList.toggle('active', i === liveIndex);
		});
		liveIndex = (liveIndex + 1) % liveItems.length;
	}
	cycleLiveHighlight();
	liveCycleInterval = setInterval(cycleLiveHighlight, 3000);
}

async function updateDemoTargets() {
	const container = document.getElementById('live-api-target__div');
	container.innerHTML = '';

	let targets = [];
	try {
		const res = await fetch('/demo-targets');
		if (!res.ok) {
			container.innerHTML = `<p style="color: var(--warning);">Failed to load demo targets.</p>`;
			return;
		}
		targets = await res.json();
	} catch {
		container.innerHTML = `<p style="color: var(--danger);">Network error loading demo targets.</p>`;
		return;
	}

	if (!Array.isArray(targets) || targets.length === 0) {
		container.innerHTML = `<p style="color: var(--info);">No demo targets available.</p>`;
		return;
	}

	for (const target of targets) {
		let checks = [];
		try {
			const checkRes = await fetch(`/demo-targets/${target.targetId}/checks`);
			if (checkRes.ok) checks = await checkRes.json();
		} catch {}
		renderStatusCard(target, checks);
	}

	startLiveCycle();
}

updateDemoTargets();
setInterval(updateDemoTargets, 30000);

window.addEventListener('DOMContentLoaded', () => {
	const items = document.querySelectorAll('.item__div');
	let currentIndex = 0;

	function cycleHighlight() {
		items.forEach((item, i) => {
			item.classList.toggle('active', i === currentIndex);
		});
		currentIndex = (currentIndex + 1) % items.length;
	}
	setTimeout(cycleHighlight, 1000);
	setInterval(cycleHighlight, 3000);
	let showingQuestion = true;
	setInterval(() => {
		const questionEl = document.getElementById('toggle-question');
		if (questionEl) {
			questionEl.textContent = showingQuestion ? '' : '?';
			showingQuestion = !showingQuestion;
		}
	}, 3000);
});

const demoTabs = document.querySelectorAll('.demo__option');
const demoPages = document.querySelectorAll('.demo-page__div');

demoTabs.forEach((tab, i) => {
	tab.addEventListener('click', () => {
		demoTabs.forEach(t => t.classList.remove('active'));
		tab.classList.add('active');
		demoPages.forEach((page, j) => {
			page.style.display = (i === j) ? 'flex' : 'none';
		});
	});
});

demoPages.forEach((page, i) => {
	page.style.display = i === 0 ? 'flex' : 'none';
});