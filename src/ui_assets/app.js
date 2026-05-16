const state = {
  graph: null,
  findings: [],
  cy: null,
  filters: {
    search: "",
    severity: "",
    service: "",
    findingsOnly: false,
    managedOnly: false,
  },
};

const $ = (selector) => document.querySelector(selector);

async function fetchJson(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`${path} returned ${response.status}`);
  }
  return response.json();
}

function serviceColor(service) {
  const colors = {
    ec2: "#2563eb",
    s3: "#0f766e",
    iam: "#7c3aed",
    lambda: "#db2777",
    rds: "#9333ea",
    kms: "#475569",
    route53: "#0891b2",
    events: "#ca8a04",
  };
  return colors[service] || "#64748b";
}

function nodeMatches(node) {
  const data = node.data();
  const search = state.filters.search.trim().toLowerCase();
  if (search) {
    const haystack = [
      data.id,
      data.label,
      data.service,
      data.resourceType,
      data.region,
      data.arn,
      data.terraformAddress,
      ...(data.findingTypes || []),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    if (!haystack.includes(search)) return false;
  }
  if (state.filters.severity) {
    const severity = data.severity || "none";
    if (severity !== state.filters.severity) return false;
  }
  if (state.filters.service && data.service !== state.filters.service) return false;
  if (state.filters.findingsOnly && !data.severity) return false;
  if (state.filters.managedOnly && !data.terraformAddress) return false;
  return true;
}

function applyFilters() {
  if (!state.cy) return;
  const visibleNodes = state.cy.nodes().filter(nodeMatches);
  state.cy.elements().addClass("hidden");
  visibleNodes.removeClass("hidden");
  state.cy.edges().filter((edge) => {
    return edge.source().visible() && edge.target().visible();
  }).removeClass("hidden");
}

function runLayout(name = $("#layout").value) {
  if (!state.cy) return;
  const layoutOptions = {
    cose: {
      name: "cose",
      animate: true,
      animationDuration: 450,
      fit: true,
      padding: 50,
      nodeRepulsion: 14000,
      idealEdgeLength: 180,
      edgeElasticity: 0.18,
      nodeOverlap: 18,
      componentSpacing: 120,
    },
    breadthfirst: {
      name: "breadthfirst",
      directed: true,
      animate: true,
      animationDuration: 350,
      padding: 45,
      spacingFactor: 1.75,
      nodeDimensionsIncludeLabels: true,
      avoidOverlap: true,
    },
    circle: {
      name: "circle",
      animate: true,
      animationDuration: 350,
      padding: 45,
    },
  };
  state.cy.layout(layoutOptions[name] || layoutOptions.cose).run();
}

function renderGraph(payload) {
  state.graph = payload;
  if (state.cy) {
    state.cy.destroy();
    state.cy = null;
  }

  populateServices(payload.summary.serviceCounts || []);
  updateSummary(payload.summary);

  if (!payload.nodes.length) {
    $("#cy").innerHTML = '<div class="empty">No AWS scan found in this map database</div>';
    return;
  }
  $("#cy").innerHTML = "";

  const elements = [
    ...payload.nodes,
    ...payload.edges,
  ];

  state.cy = cytoscape({
    container: $("#cy"),
    elements,
    minZoom: 0.08,
    maxZoom: 1.35,
    wheelSensitivity: 0.16,
    style: [
      {
        selector: "node",
        style: {
          "background-color": (ele) => serviceColor(ele.data("service")),
          "border-color": "#ffffff",
          "border-width": 2,
          "label": "data(label)",
          "font-size": 9,
          "font-weight": 700,
          "color": "#142033",
          "text-wrap": "wrap",
          "text-max-width": 86,
          "text-valign": "bottom",
          "text-halign": "center",
          "text-background-color": "#ffffff",
          "text-background-opacity": 0.85,
          "text-background-padding": 3,
          "text-margin-y": 7,
          "min-zoomed-font-size": 7,
          "width": (ele) => ele.data("terraformAddress") ? 30 : 24,
          "height": (ele) => ele.data("terraformAddress") ? 30 : 24,
        },
      },
      {
        selector: "node[severity = 'critical']",
        style: {
          "border-color": "#b91c1c",
          "border-width": 5,
          "width": 36,
          "height": 36,
        },
      },
      {
        selector: "node[severity = 'high']",
        style: {
          "border-color": "#c2410c",
          "border-width": 4,
        },
      },
      {
        selector: "node[terraformAddress]",
        style: {
          "shape": "round-rectangle",
        },
      },
      {
        selector: "edge",
        style: {
          "curve-style": "bezier",
          "target-arrow-shape": "triangle",
          "target-arrow-color": "#9aa7b8",
          "line-color": "#9aa7b8",
          "width": 1.3,
          "opacity": 0.74,
        },
      },
      {
        selector: ".hidden",
        style: {
          "display": "none",
        },
      },
      {
        selector: ":selected",
        style: {
          "overlay-color": "#0f766e",
          "overlay-opacity": 0.16,
          "overlay-padding": 8,
        },
      },
    ],
  });

  state.cy.on("tap", "node", (event) => showNode(event.target.data()));
  state.cy.on("tap", "edge", (event) => showEdge(event.target.data()));
  state.cy.on("tap", (event) => {
    if (event.target === state.cy) showEmptySelection();
  });

  runLayout();
}

function updateSummary(summary) {
  $("#metric-resources").textContent = summary.resources || 0;
  $("#metric-edges").textContent = summary.relationships || 0;
  $("#metric-managed").textContent = summary.managedResources || 0;
  $("#metric-risk").textContent = (summary.criticalFindings || 0) + (summary.highFindings || 0);
  $("#graph-subtitle").textContent = summary.scanId || "no scan";
  $("#db-line").textContent = summary.accountId ? `account ${summary.accountId}` : "map.db";
  $("#scan-line").textContent = summary.collectedAt ? `scan ${formatDate(summary.collectedAt)}` : "no scan loaded";
}

function populateServices(counts) {
  const select = $("#service");
  const current = select.value;
  const services = [...new Set(counts.map((row) => row.service))].sort();
  select.innerHTML = '<option value="">All services</option>' + services.map((service) => {
    return `<option value="${escapeHtml(service)}">${escapeHtml(service)}</option>`;
  }).join("");
  select.value = services.includes(current) ? current : "";

  $("#service-list").innerHTML = counts.slice(0, 18).map((row) => {
    return `<div class="service-row"><span>${escapeHtml(row.service)} / ${escapeHtml(row.resourceType)}</span><span>${row.count}</span></div>`;
  }).join("");
}

function renderFindings(payload) {
  state.findings = payload.findings || [];
  const container = $("#findings");
  if (!state.findings.length) {
    container.innerHTML = '<div class="empty">No compare findings</div>';
    return;
  }
  container.innerHTML = state.findings.map((finding, index) => {
    return `
      <div class="finding-item severity-${escapeHtml(finding.severity)}" data-index="${index}">
        <span class="badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
        <div class="selected-title">${escapeHtml(finding.finding_type)}</div>
        <div class="finding-meta">${escapeHtml(finding.aws_uid || finding.terraform_address || finding.id)}</div>
      </div>
    `;
  }).join("");
  container.querySelectorAll(".finding-item").forEach((item) => {
    item.addEventListener("click", () => {
      const finding = state.findings[Number(item.dataset.index)];
      showFinding(finding);
      if (finding.aws_uid && state.cy) {
        const node = state.cy.getElementById(finding.aws_uid);
        if (node.length) {
          state.cy.elements().unselect();
          node.select();
          state.cy.animate({ center: { eles: node }, zoom: Math.max(state.cy.zoom(), 1.1) }, { duration: 250 });
        }
      }
    });
  });
}

function showEmptySelection() {
  $("#selection").className = "empty";
  $("#selection").textContent = "Select a node or finding";
}

function showNode(data) {
  $("#selection").className = "";
  $("#selection").innerHTML = `
    <div class="selected-title">${escapeHtml(data.label)}</div>
    <div class="selected-meta">${escapeHtml(data.id)}</div>
    <div class="kv">
      ${kv("service", data.service)}
      ${kv("type", data.resourceType)}
      ${kv("region", data.region)}
      ${kv("terraform", data.terraformAddress || "unmanaged")}
      ${kv("finding", (data.findingTypes || []).join(", ") || "none")}
      ${kv("arn", data.arn || "n/a")}
    </div>
  `;
}

function showEdge(data) {
  $("#selection").className = "";
  $("#selection").innerHTML = `
    <div class="selected-title">${escapeHtml(data.relationshipType)}</div>
    <div class="selected-meta">${escapeHtml(data.id)}</div>
    <div class="kv">
      ${kv("from", data.source)}
      ${kv("to", data.target)}
    </div>
  `;
}

function showFinding(finding) {
  $("#selection").className = "";
  $("#selection").innerHTML = `
    <span class="badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
    <div class="selected-title">${escapeHtml(finding.finding_type)}</div>
    <div class="selected-meta">${escapeHtml(finding.reason)}</div>
    <div class="kv">
      ${kv("resource", finding.aws_uid || "n/a")}
      ${kv("terraform", finding.terraform_address || "n/a")}
      ${kv("blast", (finding.blast_radius || []).join(", ") || "none")}
      ${kv("action", finding.recommended_action)}
    </div>
  `;
}

function kv(key, value) {
  return `<div><span>${escapeHtml(key)}</span><span>${escapeHtml(String(value))}</span></div>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function bindControls() {
  $("#search").addEventListener("input", (event) => {
    state.filters.search = event.target.value;
    applyFilters();
  });
  $("#severity").addEventListener("change", (event) => {
    state.filters.severity = event.target.value;
    applyFilters();
  });
  $("#service").addEventListener("change", (event) => {
    state.filters.service = event.target.value;
    applyFilters();
  });
  $("#findings-only").addEventListener("change", (event) => {
    state.filters.findingsOnly = event.target.checked;
    applyFilters();
  });
  $("#managed-only").addEventListener("change", (event) => {
    state.filters.managedOnly = event.target.checked;
    applyFilters();
  });
  $("#layout").addEventListener("change", (event) => runLayout(event.target.value));
  $("#fit").addEventListener("click", () => state.cy && state.cy.fit(undefined, 45));
  $("#reset").addEventListener("click", () => {
    state.filters = { search: "", severity: "", service: "", findingsOnly: false, managedOnly: false };
    $("#search").value = "";
    $("#severity").value = "";
    $("#service").value = "";
    $("#findings-only").checked = false;
    $("#managed-only").checked = false;
    applyFilters();
    state.cy && state.cy.fit(undefined, 45);
  });
}

async function boot() {
  bindControls();
  if (!window.cytoscape) {
    $("#cy").innerHTML = '<div class="empty">Cytoscape failed to load</div>';
    return;
  }
  try {
    const [graph, findings] = await Promise.all([
      fetchJson("/api/graph"),
      fetchJson("/api/findings"),
    ]);
    renderGraph(graph);
    renderFindings(findings);
  } catch (error) {
    $("#cy").innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  }
}

boot();
