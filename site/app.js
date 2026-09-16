// AEGIS Threat Bulletin - renders the files written by `aegis publish export`.
//
// SECURITY: much of this data is attacker-controlled - malware tags, URL paths,
// commands typed into the honeypot. Every value is inserted with textContent,
// never innerHTML, so a tag named "<img onerror=...>" is shown as text instead
// of running on this page.

"use strict";

// Keep in sync with src/aegis/publish/export.py; tests/test_publish.py checks it.
const FILES = ["summary", "vendors", "watchlist", "malware_tags", "campaigns", "c2", "honeypot"];

const number = new Intl.NumberFormat("en-GB");
const percent = new Intl.NumberFormat("en-GB", { style: "percent", maximumFractionDigits: 1 });
const decimal = new Intl.NumberFormat("en-GB", { maximumFractionDigits: 2 });
const dateFormat = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
const dateTimeFormat = new Intl.DateTimeFormat("en-GB", {
  day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC",
});

function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined && options.text !== null) node.textContent = String(options.text);
  if (options.attrs) for (const [k, v] of Object.entries(options.attrs)) node.setAttribute(k, v);
  for (const child of children) if (child) node.append(child);
  return node;
}

function fmtNumber(value) {
  return value === null || value === undefined ? "–" : number.format(value);
}

function fmtDate(value) {
  if (!value) return "–";
  const d = new Date(value.length === 10 ? `${value}T00:00:00Z` : value);
  return Number.isNaN(d.getTime()) ? String(value) : dateFormat.format(d);
}

function section(id) {
  const root = document.getElementById(id);
  return {
    root,
    body: root.querySelector("[data-body]"),
    finding: root.querySelector("[data-finding]"),
    honesty: root.querySelector("[data-honesty]"),
  };
}

function empty(container, message) {
  container.replaceChildren(el("p", { className: "empty", text: message }));
}

function table(columns, rows) {
  const head = el("tr", {}, columns.map((c) => el("th", { className: c.num ? "num" : "", text: c.label, attrs: { scope: "col" } })));
  const body = rows.map((row) =>
    el("tr", {}, columns.map((c) => {
      const cell = el("td", { className: [c.num ? "num" : "", c.className || ""].join(" ").trim() });
      const value = c.render ? c.render(row) : row[c.key];
      if (value instanceof Node) cell.append(value);
      else cell.textContent = value === null || value === undefined ? "–" : String(value);
      return cell;
    })),
  );
  return el("table", {}, [el("thead", {}, [head]), el("tbody", {}, body)]);
}

// --- renderers --------------------------------------------------------------

function renderStamp(summary) {
  const stamp = document.getElementById("stamp");
  const generated = summary && summary.generated_at ? new Date(summary.generated_at) : null;
  stamp.replaceChildren();
  if (!generated || Number.isNaN(generated.getTime())) {
    stamp.textContent = "The latest bulletin could not be loaded.";
    return;
  }
  stamp.append("Bulletin generated ", el("b", { text: `${dateTimeFormat.format(generated)} UTC` }));
  const hours = (Date.now() - generated.getTime()) / 36e5;
  if (hours > 36) stamp.append(el("span", { className: "pill pill-on", text: ` ${Math.floor(hours / 24)} days old` }));
  if (summary.run_url && /^https:\/\/github\.com\//.test(summary.run_url)) {
    stamp.append(" · ", el("a", { text: "pipeline run", attrs: { href: summary.run_url } }));
  }
  if (summary.commit && /^[0-9a-f]{7,40}$/.test(summary.commit)) {
    stamp.append(" · commit ", el("span", { text: summary.commit.slice(0, 7) }));
  }
}

function renderFigures(summary) {
  const container = document.getElementById("figures");
  const c = (summary && summary.counts) || {};
  const figures = [
    { value: c.exploited_cves, label: "vulnerabilities proven to be exploited in the wild" },
    { value: c.ransomware_linked_cves, label: "of them used in ransomware campaigns", alert: true },
    { value: c.online_malware_urls, label: `web addresses serving malware right now, on ${fmtNumber(c.malware_hosts)} servers` },
    { value: c.url_campaigns, label: `distinct malware operations found by clustering ${fmtNumber(c.clustered_servers)} servers` },
  ];
  container.replaceChildren(
    ...figures.map((f) =>
      el("div", { className: "figure" }, [
        el("span", { className: `figure-value${f.alert ? " is-alert" : ""}`, text: fmtNumber(f.value) }),
        el("span", { className: "figure-label", text: f.label }),
      ]),
    ),
  );
}

function renderVendors(rows) {
  const s = section("vendors");
  if (!rows || !rows.length) return empty(s.body, "No vulnerability data in this bulletin.");
  const top = rows.slice(0, 15);
  const max = Math.max(...top.map((r) => r.exploited_cves));
  const lead = rows[0];
  const next4 = rows.slice(1, 5).reduce((sum, r) => sum + r.ransomware_linked_cves, 0);
  s.finding.textContent =
    `${lead.vendor} has ${fmtNumber(lead.exploited_cves)} actively exploited vulnerabilities, ` +
    `${fmtNumber(lead.ransomware_linked_cves)} of them tied to ransomware` +
    (next4 ? ` - against ${fmtNumber(next4)} for the next four vendors combined.` : ".");
  const grid = el("div", { className: "bars", attrs: { role: "list" } });
  for (const r of top) {
    const other = r.exploited_cves - r.ransomware_linked_cves;
    const track = el("div", { className: "bar-track", attrs: { "aria-hidden": "true" } }, [
      el("span", { className: "bar-alert", attrs: { style: `width:${(100 * r.ransomware_linked_cves) / max}%` } }),
      el("span", { className: "bar-base", attrs: { style: `width:${(100 * other) / max}%` } }),
    ]);
    const row = el("div", { attrs: { role: "listitem", style: "display:contents" } }, [
      el("span", { className: "bar-label", text: r.vendor }),
      track,
      el("span", {
        className: "bar-value",
        text: fmtNumber(r.exploited_cves),
        attrs: { title: `${r.ransomware_linked_cves} ransomware-linked (${r.ransomware_share_pct}%)` },
      }),
    ]);
    row.setAttribute("aria-label", `${r.vendor}: ${r.exploited_cves} exploited, ${r.ransomware_linked_cves} ransomware-linked`);
    grid.append(row);
  }
  s.body.replaceChildren(grid);
}

function renderWatchlist(rows, models) {
  const s = section("watchlist");
  const m = models && models.ransomware;
  if (m && m.pr_auc_time_split !== undefined && m.test_prevalence) {
    s.honesty.replaceChildren(
      el("b", { text: "How far to trust this. " }),
      `Trained only on vulnerabilities added before 2025 and tested on later ones, the model scores a PR-AUC of `,
      el("b", { text: decimal.format(m.pr_auc_time_split) }),
      ` where random guessing scores `,
      el("b", { text: decimal.format(m.test_prevalence) }),
      ` - about `,
      el("b", { text: `${decimal.format(m.pr_auc_time_split / m.test_prevalence)}×` }),
      ` better than chance. Useful for deciding what to patch first; not a verdict.`,
    );
  }
  if (!rows || !rows.length) return empty(s.body, "No watch list in this bulletin.");
  s.finding.textContent =
    "Vulnerabilities added since 2025 that are not yet linked to ransomware, ranked by how closely their descriptions resemble the ones that are. CISA often adds the ransomware flag months later.";
  s.body.replaceChildren(
    table(
      [
        { label: "#", key: "watchlist_rank", num: true },
        { label: "CVE", render: (r) => el("span", { className: "mono nowrap", text: r.cve_id }) },
        { label: "Product", render: (r) => el("span", {}, [el("b", { text: r.vendor }), " ", el("span", { className: "small", text: r.product })]) },
        { label: "Vulnerability", key: "vulnerability_name" },
        { label: "Added", render: (r) => el("span", { className: "nowrap", text: fmtDate(r.date_added) }) },
        {
          label: "Resemblance",
          render: (r) =>
            el("span", { className: "prob" }, [
              el("span", { className: "prob-track", attrs: { "aria-hidden": "true" } }, [
                el("span", { className: "prob-fill", attrs: { style: `width:${Math.round(100 * r.ransomware_probability)}%`, role: "presentation" } }),
              ]),
              el("span", { className: "mono", text: percent.format(r.ransomware_probability) }),
            ]),
        },
      ],
      rows,
    ),
  );
}

function renderTags(rows) {
  const s = section("malware_tags");
  if (!rows || !rows.length) return empty(s.body, "No URLhaus data in this bulletin.");
  const concentrated = [...rows].sort((a, b) => b.urls_per_host - a.urls_per_host)[0];
  s.finding.textContent =
    `URL counts mislead without server counts: "${rows[0].tag}" has ${fmtNumber(rows[0].urls)} URLs across ${fmtNumber(rows[0].distinct_hosts)} servers, ` +
    `while "${concentrated.tag}" packs ${decimal.format(concentrated.urls_per_host)} URLs onto each server - far easier to block.`;
  s.body.replaceChildren(
    table(
      [
        { label: "Tag", render: (r) => el("span", { className: "mono", text: r.tag }) },
        { label: "URLs", key: "urls", num: true, render: (r) => fmtNumber(r.urls) },
        { label: "Online now", num: true, render: (r) => fmtNumber(r.online_urls) },
        { label: "Servers", num: true, render: (r) => fmtNumber(r.distinct_hosts) },
        { label: "URLs per server", num: true, render: (r) => decimal.format(r.urls_per_host) },
      ],
      rows.slice(0, 15),
    ),
  );
}

function renderCampaigns(rows, models) {
  const s = section("campaigns");
  if (!rows || !rows.length) return empty(s.body, "No campaigns found in this bulletin.");
  const m = models && models.campaigns;
  s.finding.textContent =
    "Malware servers grouped by what they serve - file paths, tags, ports - without ever seeing their IP addresses." +
    (m && m.subnet_lift
      ? ` The groups still share network ranges ${decimal.format(m.subnet_lift)}× more often than random pairs, which is evidence they are real operations.`
      : "");
  s.body.replaceChildren(
    ...rows.slice(0, 9).map((c) =>
      el("article", { className: "campaign" }, [
        el("p", { className: "campaign-stats" }, [
          el("span", {}, [el("b", { text: fmtNumber(c.servers) }), " servers"]),
          el("span", {}, [el("b", { text: fmtNumber(c.urls) }), " URLs"]),
          el("span", {}, [el("b", { text: fmtNumber(c.distinct_subnets) }), " networks"]),
        ]),
        el("p", { className: "small", text: "Tags" }),
        el("ul", { className: "chips" }, (c.top_tags || []).map((t) => el("li", { text: t }))),
        el("p", { className: "small", text: "Files served" }),
        el("ul", { className: "chips" }, (c.top_paths || []).map((p) => el("li", { text: p }))),
      ]),
    ),
  );
}

function renderC2(rows) {
  const s = section("c2");
  if (!rows || !rows.length) return empty(s.body, "No botnet controllers in this bulletin.");
  const tor = rows.filter((r) => r.was_ever_tor_exit).length;
  const cloud = rows.filter((r) => r.hosting_type === "commercial_cloud").length;
  s.finding.textContent =
    `${tor === 0 ? "None" : fmtNumber(tor)} of ${fmtNumber(rows.length)} botnet control servers hide behind Tor; ` +
    `${fmtNumber(cloud)} rent mainstream cloud hosting. An answer that exists only because two feeds were joined.`;
  s.body.replaceChildren(
    table(
      [
        { label: "Address", render: (r) => el("span", { className: "mono nowrap", text: `${r.ip_address}:${r.port}` }) },
        { label: "Malware", key: "malware" },
        { label: "Status", render: (r) => el("span", { className: `pill ${r.is_online ? "pill-on" : ""}`, text: r.is_online ? "online" : "offline" }) },
        { label: "Network", render: (r) => el("span", {}, [r.as_name || "–", " ", el("span", { className: "small", text: r.country || "" })]) },
        { label: "Hosting", render: (r) => el("span", { className: `pill ${r.hosting_type === "commercial_cloud" ? "pill-accent" : ""}`, text: r.hosting_type === "commercial_cloud" ? "cloud" : "other" }) },
        { label: "Tor exit", render: (r) => (r.is_current_tor_exit ? "yes" : r.was_ever_tor_exit ? "formerly" : "no") },
      ],
      rows,
    ),
  );
}

function renderHoneypot(data) {
  const s = section("honeypot");
  if (!data || !data.available) {
    s.body.replaceChildren(
      el("div", { className: "pending" }, [
        el("p", {}, [el("b", { text: "The sensor is built but not yet deployed." })]),
        el("p", {
          text: "A decoy SSH and Telnet server on Oracle Cloud will record real attacks - passwords guessed, commands typed, malware fetched. When it goes live, this section shows them, with every attacker address replaced by a keyed pseudonym.",
        }),
      ]),
    );
    return;
  }
  const o = data.overview;
  s.finding.textContent =
    `${fmtNumber(o.sessions)} attack sessions from ${fmtNumber(o.distinct_sources)} sources since ${fmtDate(o.first_session)}. ` +
    `${fmtNumber(o.logged_in)} got a (fake) shell; ${fmtNumber(o.downloaded)} tried to download something.`;
  const list = (title, rows, unit) =>
    el("div", {}, [
      el("h3", { className: "panel-tag", text: title }),
      table([{ label: "Value", render: (r) => el("span", { className: "mono", text: r.value }) }, { label: unit, num: true, render: (r) => fmtNumber(r.attempts ?? r.sessions) }], rows),
    ]);
  const flagged = data.flagged_sessions.length
    ? el("div", {}, [
        el("h3", { className: "panel-tag", text: "Sessions unlike the rest" }),
        el("div", { className: "table-scroll" }, [
          table(
            [
              { label: "#", key: "anomaly_rank", num: true },
              { label: "Source", render: (r) => el("span", { className: "mono", text: r.source }) },
              { label: "When (UTC)", render: (r) => el("span", { className: "nowrap", text: fmtDate(r.started_at) }) },
              { label: "Why it stands out", key: "reasons" },
            ],
            data.flagged_sessions,
          ),
        ]),
      ])
    : null;
  s.body.replaceChildren(
    el("div", { className: "campaigns" }, [
      list("Usernames tried", data.top_usernames, "Attempts"),
      list("Passwords tried", data.top_passwords, "Attempts"),
      list("First commands", data.top_first_commands, "Sessions"),
    ]),
    flagged || "",
  );
}

// --- load -------------------------------------------------------------------

async function load(name) {
  const response = await fetch(`data/${name}.json`, { cache: "no-cache" });
  if (!response.ok) throw new Error(`${name}: HTTP ${response.status}`);
  return response.json();
}

async function main() {
  const results = await Promise.allSettled(FILES.map(load));
  const data = Object.fromEntries(FILES.map((name, i) => [name, results[i].status === "fulfilled" ? results[i].value : null]));
  const models = data.summary ? data.summary.models : {};
  const renderers = [
    () => renderStamp(data.summary),
    () => renderFigures(data.summary),
    () => renderVendors(data.vendors),
    () => renderWatchlist(data.watchlist, models),
    () => renderTags(data.malware_tags),
    () => renderCampaigns(data.campaigns, models),
    () => renderC2(data.c2),
    () => renderHoneypot(data.honeypot),
  ];
  for (const render of renderers) {
    try {
      render();
    } catch (error) {
      console.error(error);
    }
  }
}

main();
