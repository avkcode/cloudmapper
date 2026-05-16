const state = {
  graph: null,
  findings: [],
  findingsRunId: null,
  cy: null,
  viewMode: "graph",
  groupBy: "environment",
  theme: "light",
  spreadMode: false,
  panels: {
    inspector: true,
    findings: true,
  },
  visible: { nodes: 0, total: 0 },
  focusMode: "all",
  selection: null,
  selectedFinding: null,
  selectedNodeId: null,
  blastNodeIds: null,
  atlasSelection: null,
  attackSelection: null,
  collapsedGroups: new Set(),
  palette: {
    open: false,
    index: 0,
    filtered: [],
  },
  filters: {
    search: "",
    severity: "",
    service: "",
    environment: "",
    application: "",
    provider: "",
    namespace: "",
    owner: "",
    findingsOnly: false,
    managedOnly: false,
  },
};

const $ = (selector) => document.querySelector(selector);

const FOCUS_MODES = ["all", "risk", "unmanaged", "terraform", "blast"];
const FOCUS_MODE_META = {
  all: { label: "All", hint: "0", icon: "icon-all" },
  risk: { label: "Risk", hint: "1", icon: "icon-risk" },
  unmanaged: { label: "Unmanaged", hint: "2", icon: "icon-unmanaged" },
  terraform: { label: "Terraform", hint: "3", icon: "icon-managed" },
  blast: { label: "Blast radius", hint: "B", icon: "icon-blast" },
};
const VIEW_MODES = ["graph", "exposure", "groups", "attack", "drift", "remediation"];
const VIEW_MODE_META = {
  graph: { label: "Graph", hint: "G", icon: "icon-relation" },
  exposure: { label: "Exposure atlas", hint: "E", icon: "icon-atlas" },
  groups: { label: "Groups", hint: "L", icon: "icon-all" },
  attack: { label: "Attack paths", hint: "", icon: "icon-attack" },
  drift: { label: "Drift", hint: "", icon: "icon-drift" },
  remediation: { label: "Remediation", hint: "", icon: "icon-remediation" },
};
const GROUP_FIELDS = {
  provider: { label: "Provider", filter: "provider", nodeValue: (node) => node.provider || "unknown" },
  namespace: { label: "Namespace", filter: "namespace", nodeValue: (node) => node.namespace || "cluster" },
  application: { label: "Application", filter: "application", nodeValue: (node) => node.application || "unassigned" },
  environment: { label: "Environment", filter: "environment", nodeValue: (node) => node.environment || "untagged" },
  owner: { label: "Owner", filter: "owner", nodeValue: (node) => node.owner || "unowned" },
  severity: { label: "Severity", filter: "severity", nodeValue: (node) => node.severity || "none" },
  relationshipType: { label: "Relationship type", filter: null },
};
const THEME_STORAGE_KEY = "cloudmapper.theme";
const SEVERITY_META = {
  critical: { rank: 4, label: "critical", color: "#ff5c5c", soft: "#2a1111" },
  high: { rank: 3, label: "high", color: "#ff8a3d", soft: "#29160a" },
  medium: { rank: 2, label: "medium", color: "#f5c542", soft: "#221b08" },
  none: { rank: 1, label: "none", color: "#3f3f46", soft: "#111111" },
};

async function fetchJson(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`${path} returned ${response.status}`);
  }
  return response.json();
}

function serviceColor(service) {
  const colors = state.theme === "light"
    ? {
        ec2: "#e4e7ec",
        s3: "#dff4e8",
        iam: "#efe7ff",
        lambda: "#ffe4ec",
        rds: "#ebe7ff",
        kms: "#e5e7eb",
        route53: "#dff3f8",
        events: "#fff1d6",
        core: "#e0f2fe",
        apps: "#e9d5ff",
        networking: "#d1fae5",
        rbac: "#fee2e2",
        storage: "#ede9fe",
      }
    : {
        ec2: "#151923",
        s3: "#111f1a",
        iam: "#191522",
        lambda: "#21141b",
        rds: "#181425",
        kms: "#171717",
        route53: "#111d21",
        events: "#211b10",
        core: "#0b1f2a",
        apps: "#1d1328",
        networking: "#0f241b",
        rbac: "#271313",
        storage: "#17142a",
      };
  return colors[service] || (state.theme === "light" ? "#f4f4f5" : "#171717");
}

function cssVar(name, fallback) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

function graphTheme() {
  return {
    nodeBorder: cssVar("--node-border", "#3f3f46"),
    nodeLabel: cssVar("--node-label", "#d4d4d8"),
    nodeLabelBg: cssVar("--node-label-bg", "#050505"),
    edge: cssVar("--edge", "#4b5563"),
    overlay: cssVar("--overlay", "#fafafa"),
    critical: cssVar("--critical", "#ff5c5c"),
    high: cssVar("--high", "#ff8a3d"),
    medium: cssVar("--medium", "#f5c542"),
    managed: cssVar("--managed", "#35d399"),
    muted: cssVar("--muted", "#8f8f99"),
    surface: cssVar("--surface", "#0a0a0a"),
  };
}

function nodeShape(data) {
  if (data.severity) return "ellipse";
  if (data.provider === "k8s" && ["namespace", "node", "storage-class"].includes(data.resourceType)) return "hexagon";
  if (data.provider === "k8s" && ["service", "ingress", "network-policy"].includes(data.resourceType)) return "diamond";
  if (data.provider === "k8s" && ["secret", "configmap", "persistent-volume", "persistent-volume-claim"].includes(data.resourceType)) return "barrel";
  if (["vpc", "subnet", "security-group", "route-table", "internet-gateway", "nat-gateway"].includes(data.resourceType)) {
    return "diamond";
  }
  if (["bucket", "volume"].includes(data.resourceType)) {
    return "barrel";
  }
  return "ellipse";
}

function nodeShellColor(data) {
  if (data.severity === "critical") return state.theme === "light" ? "#fff1f2" : "#2a1111";
  if (data.severity === "high") return state.theme === "light" ? "#fff7ed" : "#29160a";
  if (data.severity === "medium") return state.theme === "light" ? "#fefce8" : "#221b08";
  return serviceColor(data.service);
}

function nodeRingColor(data, theme = graphTheme()) {
  if (data.severity === "critical") return theme.critical;
  if (data.severity === "high") return theme.high;
  if (data.severity === "medium") return theme.medium;
  if (data.terraformAddress) return theme.managed;
  return theme.nodeBorder;
}

function nodeIconColor(data, theme = graphTheme()) {
  if (data.severity === "critical") return theme.critical;
  if (data.severity === "high") return theme.high;
  if (data.severity === "medium") return theme.medium;
  if (data.terraformAddress) return theme.managed;
  return state.theme === "light" ? "#27272a" : "#e4e4e7";
}

function nodeSize(data) {
  if (data.severity === "critical") return 38;
  if (data.severity === "high") return 34;
  if (data.severity === "medium") return 32;
  if (data.terraformAddress) return 31;
  return 28;
}

function nodeIconSize(data) {
  return Math.max(15, Math.round(nodeSize(data) * 0.52));
}

function nodeIconDataUri(data, theme = graphTheme()) {
  const color = nodeIconColor(data, theme);
  const stroke = `stroke="${escapeXml(color)}"`;
  const common = `fill="none" ${stroke} stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"`;
  const type = data.resourceType || "";
  const service = data.service || "";
  let body;

  if (data.provider === "k8s" && ["deployment", "daemonset", "stateful-set", "replica-set", "pod"].includes(type)) {
    body = `<rect ${common} x="5" y="6" width="14" height="12" rx="2"/><path ${common} d="M8 10h8"/><path ${common} d="M8 14h8"/><path ${common} d="M12 6v12"/>`;
  } else if (data.provider === "k8s" && ["service", "ingress", "network-policy"].includes(type)) {
    body = `<circle ${common} cx="6" cy="12" r="2.4"/><circle ${common} cx="18" cy="7" r="2.4"/><circle ${common} cx="18" cy="17" r="2.4"/><path ${common} d="M8.2 11l7.4-3"/><path ${common} d="M8.2 13l7.4 3"/>`;
  } else if (data.provider === "k8s" && ["service-account", "role", "role-binding", "cluster-role", "cluster-role-binding"].includes(type)) {
    body = `<circle ${common} cx="8" cy="9" r="3"/><path ${common} d="M4 19c.8-3.1 2.1-4.8 4-4.8s3.2 1.7 4 4.8"/><path ${common} d="M15 8h5"/><path ${common} d="M17.5 8v7"/><path ${common} d="M15 15h5"/>`;
  } else if (data.provider === "k8s" && ["secret", "configmap", "persistent-volume", "persistent-volume-claim", "storage-class"].includes(type)) {
    body = `<path ${common} d="M6 7c0-1.7 12-1.7 12 0v10c0 1.7-12 1.7-12 0V7z"/><path ${common} d="M6 7c0 1.7 12 1.7 12 0"/><path ${common} d="M6 12c0 1.7 12 1.7 12 0"/>`;
  } else if (type === "security-group") {
    body = `<path ${common} d="M12 3.5l6.5 2.8v4.9c0 4.1-2.7 7.5-6.5 9.3-3.8-1.8-6.5-5.2-6.5-9.3V6.3L12 3.5z"/><path ${common} d="M9 12h6"/><path ${common} d="M12 9v6"/>`;
  } else if (["vpc", "subnet", "route-table", "internet-gateway", "nat-gateway"].includes(type) || service === "route53") {
    body = `<circle ${common} cx="6.5" cy="12" r="2.4"/><circle ${common} cx="17.5" cy="7" r="2.4"/><circle ${common} cx="17.5" cy="17" r="2.4"/><path ${common} d="M8.8 11l6.4-3"/><path ${common} d="M8.8 13l6.4 3"/>`;
  } else if (service === "s3" || ["bucket", "volume"].includes(type)) {
    body = `<path ${common} d="M6 7c0-1.7 12-1.7 12 0v10c0 1.7-12 1.7-12 0V7z"/><path ${common} d="M6 7c0 1.7 12 1.7 12 0"/><path ${common} d="M6 12c0 1.7 12 1.7 12 0"/>`;
  } else if (service === "rds") {
    body = `<ellipse ${common} cx="12" cy="6.5" rx="6" ry="2.5"/><path ${common} d="M6 6.5v10c0 1.4 2.7 2.5 6 2.5s6-1.1 6-2.5v-10"/><path ${common} d="M6 11.5c0 1.4 2.7 2.5 6 2.5s6-1.1 6-2.5"/>`;
  } else if (service === "lambda" || type === "function") {
    body = `<path ${common} d="M9.5 4.5h4L8.8 19.5h-4L9.5 4.5z"/><path ${common} d="M14 14.5l2.2 5h3.3"/><path ${common} d="M15.4 11h2.8"/>`;
  } else if (service === "iam") {
    body = `<circle ${common} cx="8" cy="9" r="3"/><path ${common} d="M3.8 19c.8-3.2 2.2-5 4.2-5s3.4 1.8 4.2 5"/><path ${common} d="M15 8h5"/><path ${common} d="M18 8v8"/><path ${common} d="M15.5 16h5"/>`;
  } else if (service === "kms") {
    body = `<circle ${common} cx="8" cy="12" r="3.2"/><path ${common} d="M11.2 12H21"/><path ${common} d="M17 12v3"/><path ${common} d="M20 12v3"/>`;
  } else if (type === "instance" || service === "ec2") {
    body = `<rect ${common} x="5" y="6" width="14" height="12" rx="2.2"/><path ${common} d="M8 9h8"/><path ${common} d="M8 12h3"/><path ${common} d="M13 12h3"/><path ${common} d="M8 15h8"/>`;
  } else {
    body = `<path ${common} d="M5 7l7-3.5L19 7l-7 3.5L5 7z"/><path ${common} d="M5 7v8.5l7 4 7-4V7"/><path ${common} d="M12 10.5v9"/>`;
  }

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">${body}</svg>`;
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}

function escapeXml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function nodeMatches(node) {
  const data = node.data();
  return dataMatchesFilters(data);
}

function dataMatchesFilters(data) {
  if (!nodeMatchesFocus(data)) return false;
  const search = state.filters.search.trim().toLowerCase();
  if (search) {
    const haystack = [
      data.id,
      data.label,
      data.provider,
      data.accountId,
      data.partition,
      data.service,
      data.resourceType,
      data.region,
      data.namespace,
      data.environment,
      data.application,
      data.owner,
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
  if (state.filters.provider && data.provider !== state.filters.provider) return false;
  if (state.filters.service && data.service !== state.filters.service) return false;
  if (state.filters.namespace && data.namespace !== state.filters.namespace) return false;
  if (state.filters.environment && data.environment !== state.filters.environment) return false;
  if (state.filters.application && data.application !== state.filters.application) return false;
  if (state.filters.owner && data.owner !== state.filters.owner) return false;
  if (state.filters.findingsOnly && !data.severity) return false;
  if (state.filters.managedOnly && !data.terraformAddress) return false;
  return true;
}

function nodeMatchesFocus(data) {
  if (state.focusMode === "risk") return Boolean(data.severity);
  if (state.focusMode === "unmanaged") return !data.terraformAddress;
  if (state.focusMode === "terraform") return Boolean(data.terraformAddress);
  if (state.focusMode === "blast") {
    if (state.blastNodeIds?.size) return state.blastNodeIds.has(data.id);
    return Boolean(data.severity);
  }
  return true;
}

function applyFilters() {
  if (!state.cy) {
    const nodes = currentFilteredNodeData();
    updateVisibleCount(nodes.length, state.graph?.nodes?.length || 0);
    renderFilteredPanels(nodes);
    renderCurrentView();
    return;
  }
  state.blastNodeIds = computeBlastNodeIds();
  const visibleNodes = state.cy.nodes().filter(nodeMatches);
  state.cy.elements().addClass("hidden");
  visibleNodes.removeClass("hidden");
  state.cy.edges().filter((edge) => {
    return edge.source().visible() && edge.target().visible();
  }).removeClass("hidden");
  updateVisibleCount(visibleNodes.length, state.cy.nodes().length);
  renderFilteredPanels(visibleNodes.map((node) => node.data()));
  renderCurrentView();
}

function runLayout(name = $("#layout")?.value || "breadthfirst") {
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
  populateFacets(payload.nodes || []);
  updateSummary(payload.summary);
  renderRiskSummary((payload.nodes || []).map((node) => node.data));

  if (!payload.nodes.length) {
    $("#cy").innerHTML = emptyState(
      "No scan data",
      payload.summary.scanId
        ? "This scan did not store any graphable resources."
        : "map.db has no graphable scan."
    );
    updateVisibleCount(0, 0);
    renderCurrentView();
    return;
  }
  $("#cy").innerHTML = "";

  const elements = [
    ...payload.nodes,
    ...payload.edges,
  ];
  const theme = graphTheme();

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
          "background-color": (ele) => nodeShellColor(ele.data()),
          "background-image": (ele) => nodeIconDataUri(ele.data(), theme),
          "background-fit": "contain",
          "background-width": (ele) => nodeIconSize(ele.data()),
          "background-height": (ele) => nodeIconSize(ele.data()),
          "background-opacity": 1,
          "border-color": (ele) => nodeRingColor(ele.data(), theme),
          "border-width": (ele) => ele.data("terraformAddress") || ele.data("severity") ? 2.6 : 1.5,
          "label": "data(label)",
          "font-size": 9,
          "font-weight": 650,
          "color": theme.nodeLabel,
          "text-wrap": "wrap",
          "text-max-width": 92,
          "text-valign": "bottom",
          "text-halign": "center",
          "text-background-color": theme.nodeLabelBg,
          "text-background-opacity": 0.86,
          "text-background-padding": 3,
          "text-margin-y": 8,
          "min-zoomed-font-size": 7,
          "width": (ele) => nodeSize(ele.data()),
          "height": (ele) => nodeSize(ele.data()),
          "shape": (ele) => nodeShape(ele.data()),
        },
      },
      {
        selector: "node[terraformAddress]",
        style: {
          "border-color": "#35d399",
          "border-style": "double",
        },
      },
      {
        selector: "node[severity = 'critical']",
        style: {
          "background-color": (ele) => nodeShellColor(ele.data()),
          "border-color": theme.critical,
          "border-width": 4,
        },
      },
      {
        selector: "node[severity = 'high']",
        style: {
          "background-color": (ele) => nodeShellColor(ele.data()),
          "border-color": theme.high,
          "border-width": 3.4,
        },
      },
      {
        selector: "node[severity = 'medium']",
        style: {
          "background-color": (ele) => nodeShellColor(ele.data()),
          "border-color": theme.medium,
          "border-width": 3,
        },
      },
      {
        selector: "edge",
        style: {
          "curve-style": "bezier",
          "target-arrow-shape": "triangle",
          "target-arrow-color": theme.edge,
          "line-color": theme.edge,
          "width": 1.2,
          "opacity": 0.58,
        },
      },
      {
        selector: "node.spread",
        style: {
          "text-opacity": 0.62,
          "min-zoomed-font-size": 10,
          "text-background-opacity": 0.72,
        },
      },
      {
        selector: "edge.spread",
        style: {
          "opacity": 0.18,
          "width": 0.75,
        },
      },
      {
        selector: "node.spread-focus",
        style: {
          "opacity": 1,
          "text-opacity": 1,
          "min-zoomed-font-size": 6,
          "overlay-color": theme.overlay,
          "overlay-opacity": 0.04,
          "overlay-padding": 8,
        },
      },
      {
        selector: "edge.spread-focus",
        style: {
          "opacity": 0.7,
          "width": 1.45,
        },
      },
      {
        selector: "node.spread-dim",
        style: {
          "opacity": 0.2,
          "text-opacity": 0.05,
        },
      },
      {
        selector: "edge.spread-dim",
        style: {
          "opacity": 0.05,
          "width": 0.55,
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
          "overlay-color": theme.overlay,
          "overlay-opacity": 0.1,
          "overlay-padding": 9,
        },
      },
    ],
  });

  state.cy.on("tap", "node", (event) => showNode(event.target.data()));
  state.cy.on("tap", "edge", (event) => showEdge(event.target.data()));
  state.cy.on("tap", (event) => {
    if (event.target === state.cy) clearSelection();
  });

  runLayout();
  applyFilters();
  if (state.spreadMode) setSpreadMode(true, { layout: true, updateUrl: false });
}

function updateSummary(summary) {
  $("#metric-resources").textContent = summary.resources || 0;
  $("#metric-edges").textContent = summary.relationships || 0;
  $("#metric-managed").textContent = summary.managedResources || 0;
  $("#metric-risk").textContent = (summary.criticalFindings || 0) + (summary.highFindings || 0);
  $("#graph-subtitle").textContent = summary.scanId ? shortText(summary.scanId, 34) : "no scan";
  $("#db-line").textContent = summary.accountId || "map.db";
  $("#scan-line").textContent = summary.collectedAt ? formatDate(summary.collectedAt) : "no scan";
}

function updateVisibleCount(visible, total) {
  state.visible = { nodes: visible, total };
  $("#visible-count").textContent = `${visible} / ${total}`;
  syncGraphEmptyState();
}

function syncGraphEmptyState() {
  const overlay = $("#graph-empty");
  if (!overlay) return;
  const show = state.viewMode === "graph" && state.visible.total > 0 && state.visible.nodes === 0;
  overlay.hidden = !show;
  if (!show) {
    overlay.innerHTML = "";
    return;
  }
  overlay.innerHTML = `
    <strong>No matching resources</strong>
    <span>Current filters hide every resource in this scan.</span>
    <button type="button" data-reset-view>Clear filters</button>
  `;
}

function renderCurrentView() {
  const cyContainer = $("#cy");
  const d3Container = $("#d3-view");
  const graphPane = document.querySelector(".graph-pane");
  if (!cyContainer || !d3Container) return;

  syncViewControls();
  if (graphPane) graphPane.dataset.view = state.viewMode;

  const graphActive = state.viewMode === "graph";
  cyContainer.hidden = !graphActive;
  d3Container.hidden = graphActive;
  syncGraphEmptyState();

  if (graphActive) {
    if (state.cy) {
      applySpreadClasses();
      requestAnimationFrame(() => {
        state.cy.resize();
      });
    }
    return;
  }

  if (!state.graph?.nodes?.length) {
    d3Container.innerHTML = emptyState("No scan data", "map.db has no graphable scan.");
    return;
  }
  if (!window.d3) {
    d3Container.innerHTML = emptyState("D3 library failed to load", "The bundled D3 asset was not served.");
    return;
  }

  if (state.viewMode === "exposure") {
    renderExposureAtlas();
    return;
  }
  if (state.viewMode === "attack") {
    renderAttackPaths();
    return;
  }
  if (state.viewMode === "groups") {
    renderGroupLanes();
    return;
  }
  renderD3Placeholder(VIEW_MODE_META[state.viewMode] || VIEW_MODE_META.graph);
}

function renderD3Placeholder(meta) {
  $("#d3-view").innerHTML = `
    <div class="d3-layer">
      <div class="d3-view-header">
        <span class="d3-view-title">${escapeHtml(meta.label)}</span>
      </div>
      <div class="atlas-placeholder">${iconSvg(meta.icon)}<span>${escapeHtml(meta.label)}</span></div>
    </div>
  `;
}

function renderExposureAtlas() {
  const container = $("#d3-view");
  const atlas = buildExposureAtlasData();
  if (!atlas.rows.length || !atlas.columns.length) {
    container.innerHTML = emptyState("No matching exposure", "Current filters hide all resources.");
    return;
  }

  container.innerHTML = `
    <div class="d3-layer exposure-atlas">
      <div class="d3-view-header">
        <span class="d3-view-title">Exposure Atlas</span>
        <div class="d3-view-stats">
          <span><strong>${atlas.resources}</strong> resources</span>
          <span><strong>${atlas.risky}</strong> high risk</span>
          <span><strong>${atlas.managed}</strong> Terraform</span>
        </div>
        <div class="atlas-legend">
          <span><span class="severity-dot critical"></span>critical</span>
          <span><span class="severity-dot high"></span>high</span>
          <span><span class="severity-dot medium"></span>medium</span>
          <span><span class="severity-dot managed"></span>Terraform</span>
        </div>
      </div>
      <div id="exposure-stage" class="d3-stage"></div>
    </div>
  `;

  const stage = $("#exposure-stage");
  const bounds = stage.getBoundingClientRect();
  const width = Math.max(620, Math.floor(bounds.width || 620));
  const height = Math.max(360, Math.floor(bounds.height || 420));
  const margin = {
    top: 48,
    right: 20,
    bottom: 36,
    left: Math.min(188, Math.max(120, Math.floor(width * 0.22))),
  };
  const innerWidth = Math.max(280, width - margin.left - margin.right);
  const innerHeight = Math.max(220, height - margin.top - margin.bottom);
  const columnWidth = Math.max(86, innerWidth / atlas.columns.length);
  const rowHeight = Math.max(46, Math.min(76, innerHeight / atlas.rows.length));
  const gap = 7;
  const cellWidth = Math.max(42, columnWidth - gap);
  const cellHeight = Math.max(38, rowHeight - gap);
  const managedScale = d3.scaleLinear().domain([0, 1]).range([0, cellWidth - 18]);

  const svg = d3.select(stage)
    .append("svg")
    .attr("class", "d3-svg")
    .attr("viewBox", `0 0 ${width} ${height}`)
    .attr("role", "img")
    .attr("aria-label", "Exposure atlas");

  svg.append("g")
    .selectAll("text")
    .data(atlas.columns)
    .join("text")
    .attr("class", "atlas-axis-label clickable")
    .attr("x", (column) => margin.left + column.index * columnWidth + cellWidth / 2)
    .attr("y", margin.top - 18)
    .attr("text-anchor", "middle")
    .text((column) => column.label)
    .on("click", (_event, column) => setFilter("environment", column.value || ""));

  svg.append("g")
    .selectAll("text")
    .data(atlas.rows)
    .join("text")
    .attr("class", "atlas-axis-label clickable")
    .attr("x", margin.left - 14)
    .attr("y", (row) => margin.top + row.index * rowHeight + cellHeight / 2 + 4)
    .attr("text-anchor", "end")
    .text((row) => row.label)
    .on("click", (_event, row) => setFilter("application", row.value || ""));

  const cells = svg.append("g")
    .selectAll("g")
    .data(atlas.cells)
    .join("g")
    .attr("class", (cell) => {
      const classes = ["atlas-cell"];
      if (!cell.resources) classes.push("blank");
      if (state.atlasSelection === cell.key) classes.push("selected");
      return classes.join(" ");
    })
    .attr("transform", (cell) => `translate(${margin.left + cell.columnIndex * columnWidth},${margin.top + cell.rowIndex * rowHeight})`)
    .on("click", (_event, cell) => {
      if (cell.resources) selectExposureCell(cell);
    });

  cells.append("title")
    .text((cell) => exposureCellTitle(cell));

  cells.append("rect")
    .attr("class", "atlas-cell-bg")
    .attr("width", cellWidth)
    .attr("height", cellHeight)
    .attr("rx", 6)
    .attr("fill", (cell) => severitySoftColor(cell.maxSeverity))
    .attr("stroke", (cell) => severityColor(cell.maxSeverity))
    .attr("opacity", (cell) => cell.resources ? 1 : 0.35);

  cells.append("rect")
    .attr("width", cellWidth)
    .attr("height", 4)
    .attr("rx", 2)
    .attr("fill", (cell) => severityColor(cell.maxSeverity))
    .attr("opacity", (cell) => cell.maxSeverity === "none" ? 0.18 : 0.95);

  cells.append("text")
    .attr("class", "atlas-count")
    .attr("x", 12)
    .attr("y", Math.min(30, cellHeight - 20))
    .text((cell) => cell.resources || "");

  cells.append("text")
    .attr("class", "atlas-risk-text")
    .attr("x", cellWidth - 12)
    .attr("y", 22)
    .attr("text-anchor", "end")
    .text((cell) => shortRiskText(cell));

  cells.append("text")
    .attr("class", "atlas-subtext")
    .attr("x", 12)
    .attr("y", cellHeight - 12)
    .text((cell) => cell.resources ? `${cell.managed}/${cell.resources} tf` : "");

  cells.append("rect")
    .attr("class", "atlas-managed-bg")
    .attr("x", 9)
    .attr("y", cellHeight - 7)
    .attr("width", cellWidth - 18)
    .attr("height", 3)
    .attr("rx", 1.5);

  cells.append("rect")
    .attr("class", "atlas-managed-bar")
    .attr("x", 9)
    .attr("y", cellHeight - 7)
    .attr("width", (cell) => managedScale(cell.resources ? cell.managed / cell.resources : 0))
    .attr("height", 3)
    .attr("rx", 1.5);
}

function buildExposureAtlasData() {
  const nodes = graphNodeData().filter(dataMatchesFilters);
  const nodeById = new Map(graphNodeData().map((node) => [node.id, node]));
  const visibleIds = new Set(nodes.map((node) => node.id));
  const cellByKey = new Map();

  for (const node of nodes) {
    const cell = exposureCellFor(cellByKey, node.application || null, node.environment || null);
    cell.resources += 1;
    cell.nodeIds.add(node.id);
    if (node.terraformAddress) cell.managed += 1;
    if (node.service) cell.services.add(node.service);
    if (node.owner) cell.owners.add(node.owner);
    if (node.severity) increment(cell.severityCounts, node.severity);
    cell.maxSeverity = maxSeverityName(cell.maxSeverity, node.severity || "none");
    if (severityRank(node.severity) >= severityRank("high")) cell.riskyNodeIds.add(node.id);
  }

  for (const finding of state.findings) {
    if (!finding.aws_uid || !visibleIds.has(finding.aws_uid)) continue;
    const node = nodeById.get(finding.aws_uid);
    if (!node) continue;
    const cell = exposureCellFor(cellByKey, node.application || null, node.environment || null);
    cell.findings.push(finding);
    increment(cell.findingCounts, finding.severity);
    cell.maxSeverity = maxSeverityName(cell.maxSeverity, finding.severity || "none");
    if (["unmanaged_public_resource", "terraform_owned_public_ingress"].includes(finding.finding_type)) {
      cell.publicIngress += 1;
    }
    for (const uid of finding.blast_radius || []) cell.blastRadius.add(uid);
  }

  const rowMap = new Map();
  const columnMap = new Map();
  for (const cell of cellByKey.values()) {
    const row = bucketFor(rowMap, cell.applicationLabel, cell.applicationValue);
    const column = bucketFor(columnMap, cell.environmentLabel, cell.environmentValue);
    addCellToBucket(row, cell);
    addCellToBucket(column, cell);
  }

  const rows = [...rowMap.values()]
    .sort(compareExposureBuckets)
    .map((row, index) => ({ ...row, index }));
  const columns = [...columnMap.values()]
    .sort(compareEnvironmentBuckets)
    .map((column, index) => ({ ...column, index }));
  const rowIndex = new Map(rows.map((row) => [row.key, row.index]));
  const columnIndex = new Map(columns.map((column) => [column.key, column.index]));

  const cells = [];
  for (const row of rows) {
    for (const column of columns) {
      const key = exposureKey(row.value, column.value);
      const cell = finalizeExposureCell(
        cellByKey.get(key) || emptyExposureCell(row.value, column.value),
        rowIndex.get(row.key),
        columnIndex.get(column.key),
      );
      cells.push(cell);
    }
  }

  return {
    rows,
    columns,
    cells,
    resources: nodes.length,
    managed: nodes.filter((node) => node.terraformAddress).length,
    risky: nodes.filter((node) => severityRank(node.severity) >= severityRank("high")).length,
  };
}

function graphNodeData() {
  return (state.graph?.nodes || []).map((node) => node.data);
}

function currentFilteredNodeData() {
  return graphNodeData().filter(dataMatchesFilters);
}

function renderFilteredPanels(nodes = currentFilteredNodeData()) {
  renderRiskSummary(nodes);
  renderFindingList(nodes);
}

function filteredFindingList(nodes = currentFilteredNodeData()) {
  if (!state.findings.length) return [];
  const visibleIds = new Set(nodes.map((node) => node.id));
  return state.findings.filter((finding) => findingMatchesNodeScope(finding, visibleIds)).sort(compareFindings);
}

function findingMatchesNodeScope(finding, visibleIds) {
  if (state.filters.severity && finding.severity !== state.filters.severity) return false;
  const relatedIds = findingRelatedNodeIds(finding);
  if (relatedIds.length) return relatedIds.some((id) => visibleIds.has(id));
  return !hasActiveGraphFilters();
}

function findingRelatedNodeIds(finding) {
  return [
    finding.aws_uid,
    ...(Array.isArray(finding.blast_radius) ? finding.blast_radius : []),
  ].filter(Boolean);
}

function hasActiveGraphFilters() {
  const filters = state.filters;
  return Boolean(
    filters.search ||
    filters.severity ||
    filters.service ||
    filters.environment ||
    filters.application ||
    filters.provider ||
    filters.namespace ||
    filters.owner ||
    filters.findingsOnly ||
    filters.managedOnly ||
    state.focusMode !== "all"
  );
}

function exposureCellFor(map, applicationValue, environmentValue) {
  const key = exposureKey(applicationValue, environmentValue);
  if (!map.has(key)) map.set(key, emptyExposureCell(applicationValue, environmentValue));
  return map.get(key);
}

function emptyExposureCell(applicationValue, environmentValue) {
  return {
    key: exposureKey(applicationValue, environmentValue),
    applicationValue,
    environmentValue,
    applicationLabel: applicationValue || "shared",
    environmentLabel: environmentValue || "untagged",
    resources: 0,
    managed: 0,
    publicIngress: 0,
    maxSeverity: "none",
    nodeIds: new Set(),
    riskyNodeIds: new Set(),
    blastRadius: new Set(),
    services: new Set(),
    owners: new Set(),
    findings: [],
    severityCounts: new Map(),
    findingCounts: new Map(),
  };
}

function finalizeExposureCell(cell, rowIndex, columnIndex) {
  return {
    ...cell,
    rowIndex,
    columnIndex,
    nodeIds: [...cell.nodeIds],
    riskyNodeIds: [...cell.riskyNodeIds],
    blastRadius: [...cell.blastRadius],
    services: [...cell.services].sort(),
    owners: [...cell.owners].sort(),
    severityCounts: Object.fromEntries(cell.severityCounts),
    findingCounts: Object.fromEntries(cell.findingCounts),
    findings: [...cell.findings].sort(compareFindings),
  };
}

function exposureKey(applicationValue, environmentValue) {
  return `${applicationValue || ""}\u0000${environmentValue || ""}`;
}

function bucketFor(map, label, value) {
  const key = value || "";
  if (!map.has(key)) {
    map.set(key, {
      key,
      value,
      label,
      resources: 0,
      managed: 0,
      critical: 0,
      high: 0,
      medium: 0,
      findings: 0,
    });
  }
  return map.get(key);
}

function addCellToBucket(bucket, cell) {
  bucket.resources += cell.resources;
  bucket.managed += cell.managed;
  bucket.critical += cell.severityCounts.get("critical") || 0;
  bucket.high += cell.severityCounts.get("high") || 0;
  bucket.medium += cell.severityCounts.get("medium") || 0;
  bucket.findings += cell.findings.length;
}

function compareExposureBuckets(left, right) {
  return bucketScore(right) - bucketScore(left) || right.resources - left.resources || left.label.localeCompare(right.label);
}

function compareEnvironmentBuckets(left, right) {
  return environmentRank(left.label) - environmentRank(right.label) || compareExposureBuckets(left, right);
}

function bucketScore(bucket) {
  return bucket.critical * 10000 + bucket.high * 1000 + bucket.medium * 100 + bucket.findings;
}

function environmentRank(value) {
  const ranks = { prod: 0, stage: 1, dev: 2, shared: 3, global: 4, untagged: 5 };
  return ranks[value] ?? 10;
}

function compareFindings(left, right) {
  return severityRank(right.severity) - severityRank(left.severity) || left.finding_type.localeCompare(right.finding_type);
}

function selectExposureCell(cell) {
  state.atlasSelection = cell.key;
  state.attackSelection = null;
  state.selectedFinding = null;
  state.selectedNodeId = null;
  state.selection = { type: "exposure", data: cell };
  applyFilterUpdate(() => {
    state.filters.environment = cell.environmentValue || "";
    state.filters.application = cell.applicationValue || "";
  });
  selectGraphNodesByIds(cell.nodeIds);
  showExposureSelection(cell);
  renderCurrentView();
}

function selectGraphNodesByIds(ids) {
  if (!state.cy) return;
  state.cy.elements().unselect();
  const nodes = ids
    .map((id) => state.cy.getElementById(id))
    .filter((node) => node.length);
  if (!nodes.length) return;
  const collection = state.cy.collection(nodes);
  collection.select();
  if (state.viewMode === "graph") {
    state.cy.animate({ center: { eles: collection }, zoom: Math.max(state.cy.zoom(), 0.82) }, { duration: 250 });
  }
}

function showExposureSelection(cell) {
  $("#selection").className = "";
  $("#selection").innerHTML = `
    <div class="selected-title">${escapeHtml(cell.applicationLabel)} / ${escapeHtml(cell.environmentLabel)}</div>
    <div class="selected-meta">${escapeHtml(shortRiskLabel(cell))}</div>
    <div class="kv">
      ${kv("resources", cell.resources)}
      ${kv("terraform", `${cell.managed} / ${cell.resources}`)}
      ${kv("findings", cell.findings.length)}
      ${kv("public ingress", cell.publicIngress)}
      ${kv("blast radius", cell.blastRadius.length)}
      ${kv("services", cell.services.join(", ") || "n/a")}
      ${kv("owners", cell.owners.join(", ") || "n/a")}
    </div>
    ${jsonDetails("Top findings", cell.findings.slice(0, 8).map(compactFinding))}
  `;
}

function renderAttackPaths() {
  const container = $("#d3-view");
  const paths = buildAttackPathData();
  if (!paths.findings.length) {
    container.innerHTML = emptyState("No public attack paths", "Current filters hide public ingress findings.");
    return;
  }

  container.innerHTML = `
    <div class="d3-layer attack-paths">
      <div class="d3-view-header">
        <span class="d3-view-title">Attack Paths</span>
        <div class="d3-view-stats">
          <span><strong>${paths.findings.length}</strong> public findings</span>
          <span><strong>${paths.routes}</strong> public routes</span>
          <span><strong>${paths.targets}</strong> exposed targets</span>
          <span><strong>${paths.downstream}</strong> downstream</span>
        </div>
        <div class="atlas-legend">
          <span><span class="severity-dot critical"></span>critical</span>
          <span><span class="severity-dot high"></span>high</span>
          <span><span class="severity-dot managed"></span>tag-linked data</span>
        </div>
      </div>
      <div id="attack-stage" class="d3-stage attack-stage"></div>
    </div>
  `;

  const stage = $("#attack-stage");
  const bounds = stage.getBoundingClientRect();
  const width = Math.max(740, Math.floor(bounds.width || 740));
  const margin = { top: 52, right: 28, bottom: 28, left: 24 };
  const nodeWidth = Math.max(112, Math.min(154, Math.floor((width - margin.left - margin.right) / paths.layers.length) - 22));
  const nodeHeight = 43;
  const rowGap = 56;
  const maxLayerSize = Math.max(...paths.layers.map((layer) => layer.nodes.length));
  const height = Math.max(Math.floor(bounds.height || 440), margin.top + margin.bottom + maxLayerSize * rowGap + 38);
  const x = d3.scalePoint()
    .domain(paths.layers.map((layer) => layer.id))
    .range([margin.left, width - margin.right - nodeWidth])
    .padding(0.42);
  const linkWidth = d3.scaleSqrt()
    .domain([1, Math.max(1, d3.max(paths.links, (link) => link.count) || 1)])
    .range([1.2, 7]);

  for (const layer of paths.layers) {
    const startY = margin.top + 36;
    layer.nodes.forEach((node, index) => {
      node.x = x(layer.id);
      node.y = startY + index * rowGap;
      node.width = nodeWidth;
      node.height = nodeHeight;
    });
  }

  const nodeMap = new Map(paths.nodes.map((node) => [node.id, node]));
  const svg = d3.select(stage)
    .append("svg")
    .attr("class", "d3-svg attack-svg")
    .attr("viewBox", `0 0 ${width} ${height}`)
    .style("height", `${height}px`)
    .attr("role", "img")
    .attr("aria-label", "Attack path view");

  const defs = svg.append("defs");
  defs.append("marker")
    .attr("id", "attack-arrow")
    .attr("viewBox", "0 0 10 10")
    .attr("refX", 9)
    .attr("refY", 5)
    .attr("markerWidth", 5)
    .attr("markerHeight", 5)
    .attr("orient", "auto-start-reverse")
    .append("path")
    .attr("d", "M 0 0 L 10 5 L 0 10 z")
    .attr("fill", cssVar("--muted", "#8f8f99"));

  svg.append("g")
    .selectAll("text")
    .data(paths.layers)
    .join("text")
    .attr("class", "attack-column-label")
    .attr("x", (layer) => x(layer.id) + nodeWidth / 2)
    .attr("y", 25)
    .attr("text-anchor", "middle")
    .text((layer) => layer.label);

  const link = svg.append("g")
    .attr("class", "attack-links")
    .selectAll("path")
    .data(paths.links)
    .join("path")
    .attr("class", (item) => `attack-link${item.inferred ? " inferred" : ""}`)
    .attr("d", (item) => attackLinkPath(nodeMap.get(item.source), nodeMap.get(item.target)))
    .attr("stroke", (item) => severityColor(item.severity))
    .attr("stroke-width", (item) => linkWidth(item.count))
    .attr("marker-end", "url(#attack-arrow)");

  link.append("title")
    .text((item) => `${item.label || "path"}: ${item.count}`);

  svg.append("g")
    .attr("class", "attack-link-labels")
    .selectAll("text")
    .data(paths.links.filter((item) => item.count > 1))
    .join("text")
    .attr("class", "attack-link-label")
    .attr("x", (item) => {
      const source = nodeMap.get(item.source);
      const target = nodeMap.get(item.target);
      return (source.x + source.width + target.x) / 2;
    })
    .attr("y", (item) => {
      const source = nodeMap.get(item.source);
      const target = nodeMap.get(item.target);
      return (source.y + target.y) / 2 + 2;
    })
    .text((item) => item.count);

  const nodes = svg.append("g")
    .selectAll("g")
    .data(paths.nodes)
    .join("g")
    .attr("class", (node) => {
      const classes = ["attack-node", `attack-${node.kind}`];
      if (state.attackSelection === node.id) classes.push("selected");
      return classes.join(" ");
    })
    .attr("transform", (node) => `translate(${node.x},${node.y})`)
    .on("click", (_event, node) => selectAttackNode(node));

  nodes.append("title")
    .text((node) => attackNodeTitle(node));

  nodes.append("rect")
    .attr("class", "attack-node-bg")
    .attr("width", nodeWidth)
    .attr("height", nodeHeight)
    .attr("rx", 7)
    .attr("fill", (node) => attackNodeFill(node))
    .attr("stroke", (node) => severityColor(node.severity));

  nodes.append("text")
    .attr("class", "attack-node-title")
    .attr("x", 10)
    .attr("y", 17)
    .text((node) => shortText(node.label, Math.max(11, Math.floor(nodeWidth / 8))));

  nodes.append("text")
    .attr("class", "attack-node-meta")
    .attr("x", 10)
    .attr("y", 33)
    .text((node) => shortText(attackNodeMeta(node), Math.max(12, Math.floor(nodeWidth / 7))));

  nodes.append("text")
    .attr("class", "attack-node-count")
    .attr("x", nodeWidth - 9)
    .attr("y", 17)
    .attr("text-anchor", "end")
    .text((node) => node.count > 1 ? node.count : "");
}

function buildAttackPathData() {
  const nodeIndex = new Map(graphNodeData().map((node) => [node.id, node]));
  const visibleNodes = graphNodeData().filter(dataMatchesFilters);
  const visibleIds = new Set(visibleNodes.map((node) => node.id));
  const attackNodes = new Map();
  const attackLinks = new Map();
  const routeKeys = new Set();
  const targetIds = new Set();
  const downstreamIds = new Set();
  const pathFindings = [];

  const internet = ensureAttackNode(attackNodes, {
    id: "external:internet",
    kind: "external",
    layer: "external",
    label: "Internet",
    detail: "public ingress",
    severity: "high",
  });

  const findings = state.findings.filter((finding) => {
    return finding.aws_uid && visibleIds.has(finding.aws_uid) && publicIngressRules(finding).length;
  }).sort(compareFindings);

  for (const finding of findings) {
    const securityGroup = nodeIndex.get(finding.aws_uid);
    if (!securityGroup) continue;
    pathFindings.push(finding);
    const sgNode = ensureAttackNode(attackNodes, {
      id: `security:${finding.aws_uid}`,
      kind: "security",
      layer: "security",
      label: securityGroup.label || securityGroup.name || securityGroup.id,
      detail: `${securityGroup.region || ""} ${securityGroup.application || ""}`.trim(),
      severity: finding.severity,
      resourceIds: [finding.aws_uid],
      findings: [finding],
      application: securityGroup.application || null,
      environment: securityGroup.environment || null,
      owner: securityGroup.owner || null,
    });
    sgNode.publicIngress += publicIngressRules(finding).length;

    for (const rule of publicIngressRules(finding)) {
      const portLabel = publicPortLabel(rule);
      const portNode = ensureAttackNode(attackNodes, {
        id: `port:${portLabel}`,
        kind: "port",
        layer: "ingress",
        label: portLabel,
        detail: "public listener",
        severity: finding.severity,
        findings: [finding],
      });

      for (const source of publicSourceLabels(rule)) {
        const routeKey = `${finding.id}:${source}:${portLabel}`;
        routeKeys.add(routeKey);
        internet.count += 1;

        const sourceNode = ensureAttackNode(attackNodes, {
          id: `source:${source}`,
          kind: "source",
          layer: "source",
          label: source,
          detail: source === "::/0" ? "IPv6 public" : "IPv4 public",
          severity: finding.severity,
          findings: [finding],
        });
        sourceNode.count += 1;
        portNode.count += 1;
        sgNode.count += 1;
        addAttackLink(attackLinks, internet.id, sourceNode.id, { count: 1, severity: finding.severity, label: "public source" });
        addAttackLink(attackLinks, sourceNode.id, portNode.id, { count: 1, severity: finding.severity, label: portLabel });
        addAttackLink(attackLinks, portNode.id, sgNode.id, { count: 1, severity: finding.severity, label: finding.finding_type });
      }
    }

    const blastGroups = attackBlastGroups(finding, nodeIndex);
    for (const group of blastGroups) {
      for (const uid of group.resourceIds) targetIds.add(uid);
      const workloadNode = ensureAttackNode(attackNodes, {
        id: group.id,
        kind: "workload",
        layer: "workload",
        label: group.label,
        detail: group.detail,
        severity: finding.severity,
        resourceIds: group.resourceIds,
        findings: [finding],
        application: group.application,
        environment: group.environment,
        owner: group.owner,
      });
      workloadNode.count = Math.max(workloadNode.count, group.resourceIds.length);
      addAttackLink(attackLinks, sgNode.id, workloadNode.id, {
        count: Math.max(1, group.resourceIds.length),
        severity: finding.severity,
        label: "blast radius",
      });

      const downstream = attackDownstreamResources(finding, group, nodeIndex);
      for (const downstreamGroup of downstream) {
        downstreamGroup.resourceIds.forEach((uid) => downstreamIds.add(uid));
        const downstreamNode = ensureAttackNode(attackNodes, {
          id: downstreamGroup.id,
          kind: downstreamGroup.kind,
          layer: "downstream",
          label: downstreamGroup.label,
          detail: downstreamGroup.detail,
          severity: finding.severity,
          resourceIds: downstreamGroup.resourceIds,
          findings: [finding],
          application: downstreamGroup.application || group.application,
          environment: downstreamGroup.environment || group.environment,
          owner: downstreamGroup.owner || group.owner,
        });
        downstreamNode.count = Math.max(downstreamNode.count, downstreamGroup.resourceIds.length);
        addAttackLink(attackLinks, workloadNode.id, downstreamNode.id, {
          count: Math.max(1, downstreamGroup.resourceIds.length),
          severity: finding.severity,
          label: downstreamGroup.relation,
          inferred: downstreamGroup.inferred,
        });
      }
    }
  }

  const layers = [
    { id: "external", label: "Entry" },
    { id: "source", label: "Source" },
    { id: "ingress", label: "Ingress" },
    { id: "security", label: "Security group" },
    { id: "workload", label: "Targets" },
    { id: "downstream", label: "Reach" },
  ].map((layer) => ({
    ...layer,
    nodes: [...attackNodes.values()]
      .filter((node) => node.layer === layer.id)
      .sort(compareAttackNodes),
  }));

  return {
    nodes: layers.flatMap((layer) => layer.nodes),
    links: [...attackLinks.values()].sort((left, right) => severityRank(right.severity) - severityRank(left.severity) || right.count - left.count),
    layers,
    findings: pathFindings,
    routes: routeKeys.size,
    targets: targetIds.size,
    downstream: downstreamIds.size,
  };
}

function ensureAttackNode(nodes, next) {
  if (!nodes.has(next.id)) {
    nodes.set(next.id, {
      id: next.id,
      kind: next.kind,
      layer: next.layer,
      label: next.label,
      detail: next.detail || "",
      severity: next.severity || "none",
      count: 0,
      publicIngress: 0,
      resourceIds: [],
      findings: [],
      application: next.application || null,
      environment: next.environment || null,
      owner: next.owner || null,
    });
  }
  const node = nodes.get(next.id);
  node.severity = maxSeverityName(node.severity, next.severity || "none");
  if (next.detail && !node.detail) node.detail = next.detail;
  if (next.application && !node.application) node.application = next.application;
  if (next.environment && !node.environment) node.environment = next.environment;
  if (next.owner && !node.owner) node.owner = next.owner;
  mergeUnique(node.resourceIds, next.resourceIds || []);
  mergeUnique(node.findings, next.findings || [], (finding) => finding.id);
  return node;
}

function addAttackLink(links, source, target, next) {
  if (!source || !target || source === target) return;
  const key = `${source}\u0000${target}\u0000${next.label || ""}\u0000${next.inferred ? "inferred" : "direct"}`;
  if (!links.has(key)) {
    links.set(key, {
      source,
      target,
      label: next.label || "",
      count: 0,
      severity: "none",
      inferred: Boolean(next.inferred),
    });
  }
  const link = links.get(key);
  link.count += next.count || 1;
  link.severity = maxSeverityName(link.severity, next.severity || "none");
}

function publicIngressRules(finding) {
  return Array.isArray(finding.attributes?.public_ingress) ? finding.attributes.public_ingress : [];
}

function publicSourceLabels(rule) {
  const labels = [];
  for (const value of rule.ipv4_ranges || []) labels.push(value);
  for (const value of rule.ipv6_ranges || []) labels.push(value);
  return labels.length ? [...new Set(labels)] : ["public"];
}

function publicPortLabel(rule) {
  const protocol = rule.ip_protocol || rule.protocol || "tcp";
  const from = rule.from_port ?? rule.fromPort ?? "";
  const to = rule.to_port ?? rule.toPort ?? "";
  const ports = from === "" && to === "" ? "all" : from === to ? from : `${from}-${to}`;
  return `${protocol}/${ports}`;
}

function attackBlastGroups(finding, nodeIndex) {
  const groups = new Map();
  for (const uid of finding.blast_radius || []) {
    const node = nodeIndex.get(uid);
    if (!node) continue;
    const key = [
      finding.aws_uid,
      node.provider || "",
      node.service || "",
      node.resourceType || "",
      node.region || "",
      node.namespace || "",
    ].join("\u0000");
    if (!groups.has(key)) {
      groups.set(key, {
        id: `workload:${key}`,
        provider: node.provider,
        service: node.service,
        resourceType: node.resourceType,
        region: node.region,
        namespace: node.namespace,
        application: node.application || null,
        environment: node.environment || null,
        owner: node.owner || null,
        resourceIds: [],
      });
    }
    groups.get(key).resourceIds.push(uid);
  }

  return [...groups.values()].map((group) => ({
    ...group,
    label: attackGroupLabel(group.resourceIds.length, group.service, group.resourceType),
    detail: [group.region, group.namespace, group.application, group.environment].filter(Boolean).join(" / "),
  }));
}

function attackDownstreamResources(finding, workloadGroup, nodeIndex) {
  const groups = new Map();
  const workloadIds = new Set(workloadGroup.resourceIds);

  for (const edge of state.graph?.edges || []) {
    const data = edge.data;
    let downstreamUid = null;
    let relation = data.relationshipType;
    let inferred = false;
    if (workloadIds.has(data.source) && ["assumes_role", "uses_role", "mounts", "reads_secret", "references"].includes(data.relationshipType)) {
      downstreamUid = data.target;
    } else if (workloadIds.has(data.target) && ["attached_to", "mounted_by"].includes(data.relationshipType)) {
      downstreamUid = data.source;
      relation = data.relationshipType;
    }
    if (!downstreamUid || workloadIds.has(downstreamUid)) continue;
    const node = nodeIndex.get(downstreamUid);
    if (!node) continue;
    addDownstreamGroup(groups, finding, node, relation, inferred);
  }

  for (const node of graphNodeData()) {
    if (!sameApplicationDataTarget(node, workloadGroup)) continue;
    addDownstreamGroup(groups, finding, node, "tag-linked data", true);
  }

  return [...groups.values()].map((group) => ({
    ...group,
    label: attackGroupLabel(group.resourceIds.length, group.service, group.resourceType),
    detail: [group.relation, group.region, group.namespace].filter(Boolean).join(" / "),
  }));
}

function addDownstreamGroup(groups, finding, node, relation, inferred) {
  const key = [
    finding.aws_uid,
    relation,
    node.provider || "",
    node.service || "",
    node.resourceType || "",
    node.region || "",
    node.namespace || "",
  ].join("\u0000");
  if (!groups.has(key)) {
    groups.set(key, {
      id: `downstream:${key}`,
      kind: inferred ? "data" : "downstream",
      provider: node.provider,
      service: node.service,
      resourceType: node.resourceType,
      region: node.region,
      namespace: node.namespace,
      application: node.application || null,
      environment: node.environment || null,
      owner: node.owner || null,
      relation,
      inferred,
      resourceIds: [],
    });
  }
  groups.get(key).resourceIds.push(node.id);
}

function sameApplicationDataTarget(node, workloadGroup) {
  if (node.provider !== "aws" || node.service !== "s3" || node.resourceType !== "bucket") return false;
  if (!workloadGroup.application || !workloadGroup.environment) return false;
  return node.application === workloadGroup.application && node.environment === workloadGroup.environment;
}

function attackGroupLabel(count, service, resourceType) {
  const type = resourceType || service || "resource";
  if (count === 1) return type;
  return `${count} ${type}${type.endsWith("s") ? "" : "s"}`;
}

function compareAttackNodes(left, right) {
  return severityRank(right.severity) - severityRank(left.severity)
    || right.count - left.count
    || right.resourceIds.length - left.resourceIds.length
    || left.label.localeCompare(right.label);
}

function attackNodeFill(node) {
  if (node.kind === "external" || node.kind === "source") return state.theme === "light" ? "#eef2ff" : "#101827";
  if (node.kind === "port") return state.theme === "light" ? "#f5f3ff" : "#171326";
  if (node.kind === "data") return cssVar("--managed-soft", "#0c2219");
  return severitySoftColor(node.severity);
}

function attackNodeMeta(node) {
  if (node.kind === "security") return node.detail || `${node.publicIngress} ingress`;
  if (node.kind === "workload" || node.kind === "downstream" || node.kind === "data") {
    return node.detail || `${node.resourceIds.length} resources`;
  }
  return node.detail || `${node.count} paths`;
}

function attackNodeTitle(node) {
  return [
    node.label,
    node.detail,
    `${node.resourceIds.length} resources`,
    `${node.findings.length} findings`,
    node.application ? `app: ${node.application}` : "",
    node.environment ? `env: ${node.environment}` : "",
  ].filter(Boolean).join("\n");
}

function attackLinkPath(source, target) {
  if (!source || !target) return "";
  const sourceX = source.x + source.width;
  const sourceY = source.y + source.height / 2;
  const targetX = target.x;
  const targetY = target.y + target.height / 2;
  const midX = sourceX + Math.max(36, (targetX - sourceX) * 0.55);
  return `M${sourceX},${sourceY} C${midX},${sourceY} ${midX},${targetY} ${targetX},${targetY}`;
}

function selectAttackNode(node) {
  state.attackSelection = node.id;
  state.atlasSelection = null;
  state.selectedFinding = node.findings.length === 1 ? node.findings[0] : null;
  state.selectedNodeId = node.resourceIds[0] || null;
  state.selection = { type: "attack", data: node };
  selectGraphNodesByIds(node.resourceIds);
  showAttackSelection(node);
  if (state.focusMode === "blast") applyFilters();
  else renderCurrentView();
}

function showAttackSelection(node) {
  $("#selection").className = "";
  $("#selection").innerHTML = `
    <div class="selected-title">${escapeHtml(node.label)}</div>
    <div class="selected-meta">${escapeHtml(node.detail || VIEW_MODE_META.attack.label)}</div>
    <div class="kv">
      ${kv("layer", node.layer)}
      ${kv("severity", node.severity)}
      ${kv("resources", node.resourceIds.length)}
      ${kv("findings", node.findings.length)}
      ${kv("public ingress", node.publicIngress)}
      ${kv("application", node.application || "n/a")}
      ${kv("environment", node.environment || "n/a")}
      ${kv("owner", node.owner || "n/a")}
    </div>
    ${objectList("Resources", node.resourceIds.map((uid) => nodeById(uid)?.label || uid))}
    ${jsonDetails("Findings", node.findings.slice(0, 8).map(compactFinding))}
  `;
}

function mergeUnique(target, values, keyFn = (value) => value) {
  const existing = new Set(target.map(keyFn));
  for (const value of values) {
    const key = keyFn(value);
    if (existing.has(key)) continue;
    existing.add(key);
    target.push(value);
  }
}

function shortRiskText(cell) {
  if (cell.severityCounts.critical) return `C${cell.severityCounts.critical}`;
  if (cell.severityCounts.high) return `H${cell.severityCounts.high}`;
  if (cell.severityCounts.medium) return `M${cell.severityCounts.medium}`;
  return "";
}

function shortRiskLabel(cell) {
  const parts = [];
  if (cell.severityCounts.critical) parts.push(`${cell.severityCounts.critical} critical`);
  if (cell.severityCounts.high) parts.push(`${cell.severityCounts.high} high`);
  if (cell.severityCounts.medium) parts.push(`${cell.severityCounts.medium} medium`);
  return parts.join(", ") || "no findings";
}

function exposureCellTitle(cell) {
  return [
    `${cell.applicationLabel} / ${cell.environmentLabel}`,
    `${cell.resources} resources`,
    `${cell.managed} Terraform managed`,
    shortRiskLabel(cell),
  ].join("\n");
}

function severityRank(severity) {
  return SEVERITY_META[severity || "none"]?.rank || 0;
}

function maxSeverityName(current, next) {
  return severityRank(next) > severityRank(current) ? next : current;
}

function severityColor(severity) {
  const key = severity || "none";
  if (key === "critical") return cssVar("--critical", SEVERITY_META.critical.color);
  if (key === "high") return cssVar("--high", SEVERITY_META.high.color);
  if (key === "medium") return cssVar("--medium", SEVERITY_META.medium.color);
  return cssVar("--line-strong", SEVERITY_META.none.color);
}

function severitySoftColor(severity) {
  const key = severity || "none";
  if (key === "critical") return cssVar("--critical-soft", SEVERITY_META.critical.soft);
  if (key === "high") return cssVar("--high-soft", SEVERITY_META.high.soft);
  if (key === "medium") return cssVar("--medium-soft", SEVERITY_META.medium.soft);
  return cssVar("--surface-soft", SEVERITY_META.none.soft);
}

function renderGroupLanes() {
  const container = $("#d3-view");
  const groups = buildGroupLaneData(state.groupBy);
  const groupOptions = Object.entries(GROUP_FIELDS)
    .map(([key, meta]) => `<option value="${escapeHtml(key)}"${key === state.groupBy ? " selected" : ""}>${escapeHtml(meta.label)}</option>`)
    .join("");

  if (!groups.length) {
    container.innerHTML = emptyState("No matching groups", "Current filters hide all resources.");
    return;
  }

  container.innerHTML = `
    <div class="d3-layer group-lanes">
      <div class="d3-view-header">
        <span class="d3-view-title">Groups</span>
        <label class="group-by-control">
          <span>Group by</span>
          <select id="group-by-view" aria-label="Group by">${groupOptions}</select>
        </label>
        <div class="d3-view-stats">
          <span><strong>${groups.reduce((sum, group) => sum + group.resources, 0)}</strong> resources</span>
          <span><strong>${groups.reduce((sum, group) => sum + group.relationships, 0)}</strong> relationships</span>
          <span><strong>${groups.length}</strong> groups</span>
        </div>
      </div>
      <div class="group-lane-stage">
        ${groups.map(groupLaneHtml).join("")}
      </div>
    </div>
  `;
  $("#group-by-view")?.addEventListener("change", (event) => {
    state.groupBy = event.target.value;
    updateUrlFromFilters();
    renderCurrentView();
  });
  container.querySelectorAll("[data-group-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const key = button.dataset.groupToggle;
      if (state.collapsedGroups.has(key)) state.collapsedGroups.delete(key);
      else state.collapsedGroups.add(key);
      renderCurrentView();
    });
  });
  container.querySelectorAll("[data-group-filter-key]").forEach((button) => {
    button.addEventListener("click", () => {
      const key = button.dataset.groupFilterKey;
      const value = button.dataset.groupFilterValue || "";
      if (key) setFilter(key, value);
    });
  });
  container.querySelectorAll("[data-group-select]").forEach((button) => {
    button.addEventListener("click", () => {
      const group = groups.find((candidate) => candidate.key === button.dataset.groupSelect);
      if (!group) return;
      state.selection = { type: "group", data: group };
      state.selectedFinding = null;
      state.selectedNodeId = null;
      state.atlasSelection = null;
      state.attackSelection = null;
      selectGraphNodesByIds(group.nodeIds);
      showGroupSelection(group);
    });
  });
}

function buildGroupLaneData(groupBy) {
  return groupBy === "relationshipType" ? relationshipGroups() : nodeGroups(groupBy);
}

function nodeGroups(groupBy) {
  const meta = GROUP_FIELDS[groupBy] || GROUP_FIELDS.environment;
  const groups = new Map();
  const visibleNodes = graphNodeData().filter(dataMatchesFilters);
  const visibleIds = new Set(visibleNodes.map((node) => node.id));

  for (const node of visibleNodes) {
    const value = meta.nodeValue(node);
    const group = ensureGroup(groups, groupBy, value, value);
    group.resources += 1;
    group.nodeIds.push(node.id);
    if (node.terraformAddress) group.managed += 1;
    if (node.severity) increment(group.severityCounts, node.severity);
    group.maxSeverity = maxSeverityName(group.maxSeverity, node.severity || "none");
    group.services.add(node.service);
    group.providers.add(node.provider || "unknown");
    if (node.namespace) group.namespaces.add(node.namespace);
    if (node.application) group.applications.add(node.application);
    if (node.owner) group.owners.add(node.owner);
  }

  for (const edge of state.graph?.edges || []) {
    if (!visibleIds.has(edge.data.source) || !visibleIds.has(edge.data.target)) continue;
    const source = nodeById(edge.data.source);
    const target = nodeById(edge.data.target);
    for (const node of [source, target]) {
      if (!node) continue;
      const value = meta.nodeValue(node);
      const group = ensureGroup(groups, groupBy, value, value);
      group.relationships += 0.5;
      group.relationshipTypes.add(edge.data.relationshipType);
    }
  }

  for (const finding of state.findings) {
    const node = finding.aws_uid ? nodeById(finding.aws_uid) : null;
    if (!node || !visibleIds.has(node.id)) continue;
    const value = meta.nodeValue(node);
    const group = ensureGroup(groups, groupBy, value, value);
    group.findings.push(finding);
    group.maxSeverity = maxSeverityName(group.maxSeverity, finding.severity || "none");
  }

  return finalizeGroups(groups, meta.filter);
}

function relationshipGroups() {
  const groups = new Map();
  const visibleNodes = graphNodeData().filter(dataMatchesFilters);
  const visibleIds = new Set(visibleNodes.map((node) => node.id));
  for (const edge of state.graph?.edges || []) {
    if (!visibleIds.has(edge.data.source) || !visibleIds.has(edge.data.target)) continue;
    const value = edge.data.relationshipType || "unknown";
    const group = ensureGroup(groups, "relationshipType", value, value);
    group.relationships += 1;
    group.relationshipTypes.add(value);
    for (const uid of [edge.data.source, edge.data.target]) {
      const node = nodeById(uid);
      if (!group.nodeIdSet.has(uid)) {
        group.nodeIdSet.add(uid);
        group.nodeIds.push(uid);
        group.resources += 1;
        if (node?.terraformAddress) group.managed += 1;
      }
      if (!node) continue;
      group.maxSeverity = maxSeverityName(group.maxSeverity, node.severity || "none");
      if (node.severity) increment(group.severityCounts, node.severity);
      group.services.add(node.service);
      group.providers.add(node.provider || "unknown");
      if (node.namespace) group.namespaces.add(node.namespace);
      if (node.application) group.applications.add(node.application);
      if (node.owner) group.owners.add(node.owner);
    }
  }
  return finalizeGroups(groups, null);
}

function ensureGroup(groups, groupBy, value, label) {
  const groupKey = `${groupBy}:${value || ""}`;
  if (!groups.has(groupKey)) {
    groups.set(groupKey, {
      key: groupKey,
      groupBy,
      value: value || "",
      label: label || "unassigned",
      resources: 0,
      relationships: 0,
      managed: 0,
      maxSeverity: "none",
      nodeIds: [],
      nodeIdSet: new Set(),
      findings: [],
      services: new Set(),
      providers: new Set(),
      namespaces: new Set(),
      applications: new Set(),
      owners: new Set(),
      relationshipTypes: new Set(),
      severityCounts: new Map(),
    });
  }
  return groups.get(groupKey);
}

function finalizeGroups(groups, filterKey) {
  return [...groups.values()]
    .map((group) => ({
      ...group,
      relationships: Math.round(group.relationships),
      filterKey,
      collapsed: state.collapsedGroups.has(group.key),
      services: [...group.services].filter(Boolean).sort(),
      providers: [...group.providers].filter(Boolean).sort(),
      namespaces: [...group.namespaces].filter(Boolean).sort(),
      applications: [...group.applications].filter(Boolean).sort(),
      owners: [...group.owners].filter(Boolean).sort(),
      relationshipTypes: [...group.relationshipTypes].filter(Boolean).sort(),
      severityCounts: Object.fromEntries(group.severityCounts),
      findings: group.findings.sort(compareFindings),
    }))
    .sort((left, right) => groupScore(right) - groupScore(left) || right.resources - left.resources || left.label.localeCompare(right.label));
}

function groupScore(group) {
  return severityRank(group.maxSeverity) * 10000 + group.findings.length * 100 + group.relationships;
}

function groupLaneHtml(group) {
  const canFilter = group.filterKey && group.value;
  const nodePreview = group.nodeIds.slice(0, 12).map((uid) => {
    const node = nodeById(uid);
    return node ? `<button type="button" class="group-node-chip" data-copy="${escapeHtml(node.id)}">${escapeHtml(shortText(node.label, 28))}</button>` : "";
  }).join("");
  return `
    <section class="group-card severity-${escapeHtml(group.maxSeverity)}${group.collapsed ? " collapsed" : ""}">
      <button type="button" class="group-card-head" data-group-toggle="${escapeHtml(group.key)}">
        <span class="severity-dot ${escapeHtml(group.maxSeverity)}"></span>
        <span class="group-title">${escapeHtml(group.label)}</span>
        <span class="group-count">${group.resources} nodes</span>
      </button>
      <div class="group-actions">
        <button type="button" data-group-select="${escapeHtml(group.key)}">Select</button>
        ${canFilter ? `<button type="button" data-group-filter-key="${escapeHtml(group.filterKey)}" data-group-filter-value="${escapeHtml(group.value)}">Filter</button>` : ""}
      </div>
      <div class="group-card-body">
        <div class="group-metrics">
          <span><strong>${group.relationships}</strong> edges</span>
          <span><strong>${group.findings.length}</strong> findings</span>
          <span><strong>${group.managed}</strong> Terraform</span>
        </div>
        <div class="group-meta">
          ${groupMetaLine("providers", group.providers)}
          ${groupMetaLine("namespaces", group.namespaces)}
          ${groupMetaLine("apps", group.applications)}
          ${groupMetaLine("owners", group.owners)}
          ${groupMetaLine("relations", group.relationshipTypes)}
        </div>
        <div class="group-node-list">${nodePreview}</div>
      </div>
    </section>
  `;
}

function groupMetaLine(label, values) {
  if (!values?.length) return "";
  return `<span><b>${escapeHtml(label)}</b>${escapeHtml(values.slice(0, 4).join(", "))}${values.length > 4 ? "..." : ""}</span>`;
}

function showGroupSelection(group) {
  $("#selection").className = "";
  $("#selection").innerHTML = `
    <div class="selected-title">${escapeHtml(GROUP_FIELDS[group.groupBy]?.label || "Group")}: ${escapeHtml(group.label)}</div>
    <div class="selected-meta">${group.resources} resources, ${group.relationships} relationships</div>
    <div class="kv">
      ${kv("severity", group.maxSeverity)}
      ${kv("findings", group.findings.length)}
      ${kv("terraform", group.managed)}
      ${kv("providers", group.providers.join(", ") || "n/a")}
      ${kv("namespaces", group.namespaces.join(", ") || "n/a")}
      ${kv("apps", group.applications.join(", ") || "n/a")}
      ${kv("owners", group.owners.join(", ") || "n/a")}
      ${kv("relations", group.relationshipTypes.join(", ") || "n/a")}
    </div>
    ${jsonDetails("Top findings", group.findings.slice(0, 10).map(compactFinding))}
  `;
}

function nodeById(uid) {
  return graphNodeData().find((node) => node.id === uid);
}

function computeBlastNodeIds() {
  const ids = new Set();
  if (state.selectedFinding) {
    if (state.selectedFinding.aws_uid) ids.add(state.selectedFinding.aws_uid);
    for (const uid of state.selectedFinding.blast_radius || []) ids.add(uid);
    return ids;
  }
  if (state.selectedNodeId && state.cy) {
    const node = state.cy.getElementById(state.selectedNodeId);
    if (node.length) {
      ids.add(state.selectedNodeId);
      node.connectedEdges().forEach((edge) => {
        ids.add(edge.source().id());
        ids.add(edge.target().id());
      });
      return ids;
    }
  }
  return ids;
}

function populateServices(counts) {
  const select = $("#service");
  const current = state.filters.service;
  const services = [...new Set(counts.map((row) => row.service))].sort();
  select.innerHTML = '<option value="">Service</option>' + services.map((service) => {
    return `<option value="${escapeHtml(service)}">${escapeHtml(service)}</option>`;
  }).join("");
  select.value = services.includes(current) ? current : "";
  state.filters.service = select.value;
  syncControlsFromState();

  const serviceList = $("#service-list");
  if (serviceList) {
    serviceList.innerHTML = counts.slice(0, 18).map((row) => {
      return `<div class="service-row"><span>${escapeHtml(row.service)} / ${escapeHtml(row.resourceType)}</span><span>${row.count}</span></div>`;
    }).join("");
  }
}

function populateFacets(nodes) {
  const providers = new Map();
  const namespaces = new Map();
  const environments = new Map();
  const applications = new Map();
  const owners = new Map();
  for (const node of nodes) {
    increment(providers, node.data.provider);
    increment(namespaces, node.data.namespace);
    increment(environments, node.data.environment);
    increment(applications, node.data.application);
    increment(owners, node.data.owner);
  }
  state.filters.provider = populateFacetSelect($("#provider"), "Provider", providers, state.filters.provider);
  state.filters.namespace = populateFacetSelect($("#namespace"), "Namespace", namespaces, state.filters.namespace);
  state.filters.environment = populateFacetSelect($("#environment"), "Environment", environments, state.filters.environment);
  state.filters.application = populateFacetSelect($("#application"), "Application", applications, state.filters.application);
  state.filters.owner = populateFacetSelect($("#owner"), "Owner", owners, state.filters.owner);
  syncControlsFromState();
}

function populateFacetSelect(select, label, counts, current) {
  const entries = [...counts.entries()].sort((left, right) => left[0].localeCompare(right[0]));
  select.innerHTML = `<option value="">${escapeHtml(label)}</option>` + entries.map(([value, count]) => {
    return `<option value="${escapeHtml(value)}">${escapeHtml(value)} (${count})</option>`;
  }).join("");
  select.value = entries.some(([value]) => value === current) ? current : "";
  return select.value;
}

function renderRiskSummary(nodes = currentFilteredNodeData()) {
  const filteredFindings = filteredFindingList(nodes);
  const useFindings = state.findings.length > 0;
  const criticalCount = useFindings
    ? filteredFindings.filter((finding) => finding.severity === "critical").length
    : nodes.filter((node) => node.severity === "critical").length;
  const highCount = useFindings
    ? filteredFindings.filter((finding) => finding.severity === "high").length
    : nodes.filter((node) => node.severity === "high").length;
  const chips = [];
  if (criticalCount) {
    chips.push(riskChip(`${criticalCount} critical`, { severity: "critical" }, "critical"));
  }
  if (highCount) {
    chips.push(riskChip(`${highCount} high`, { severity: "high" }, "high"));
  }

  const environment = topRiskFacet(nodes, "environment");
  const application = topRiskFacet(nodes, "application");
  const provider = topRiskFacet(nodes, "provider");
  const namespace = topRiskFacet(nodes, "namespace");
  const service = topRiskFacet(nodes, "service");
  if (provider) chips.push(riskChip(`${provider.value} ${provider.count}`, { provider: provider.value }));
  if (namespace) chips.push(riskChip(`${namespace.value} ${namespace.count}`, { namespace: namespace.value }));
  if (environment) chips.push(riskChip(`${environment.value} ${environment.count}`, { environment: environment.value }));
  if (application) chips.push(riskChip(`${application.value} ${application.count}`, { application: application.value }));
  if (service) chips.push(riskChip(`${service.value} ${service.count}`, { service: service.value }));

  const summaryPanel = $("#risk-summary");
  summaryPanel.hidden = false;
  summaryPanel.innerHTML = chips.length
    ? chips.join("")
    : '<span class="risk-empty">no high risk</span>';
}

function topRiskFacet(nodes, key) {
  const counts = new Map();
  for (const node of nodes) {
    const data = node.data || node;
    if (!data.severity || data.severity === "none") continue;
    increment(counts, data[key]);
  }
  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .map(([value, count]) => ({ value, count }))[0];
}

function riskChip(label, filters, tone = "") {
  const attrs = Object.entries(filters)
    .map(([key, value]) => `data-filter-${key}="${escapeHtml(value)}"`)
    .join(" ");
  const className = tone ? `risk-chip ${tone}` : "risk-chip";
  return `<button class="${className}" type="button" ${attrs}>${escapeHtml(label)}</button>`;
}

function increment(map, value) {
  if (!value) return;
  map.set(value, (map.get(value) || 0) + 1);
}

function renderFindings(payload) {
  state.findingsRunId = payload.run_id || null;
  state.findings = payload.findings || [];
  renderFilteredPanels();
  renderCurrentView();
}

function renderFindingList(nodes = currentFilteredNodeData()) {
  const container = $("#findings");
  if (!state.findings.length) {
    container.innerHTML = state.findingsRunId
      ? emptyState("No compare findings", "The latest compare run is clean.")
      : emptyState("No compare run", "map.db has no persisted findings.");
    return;
  }
  const findings = filteredFindingList(nodes);
  if (!findings.length) {
    container.innerHTML = emptyState("No matching findings", "Current filters hide all findings.");
    return;
  }
  container.innerHTML = findings.map((finding, index) => {
    return `
      <div class="finding-item severity-${escapeHtml(finding.severity)}" data-index="${index}" aria-label="${escapeHtml(finding.severity)} ${escapeHtml(finding.finding_type)}">
        <span class="severity-dot ${escapeHtml(finding.severity)}" title="${escapeHtml(finding.severity)}" aria-hidden="true"></span>
        <div>
          <div class="selected-title">${escapeHtml(finding.finding_type)}</div>
        </div>
      </div>
    `;
  }).join("");
  container.querySelectorAll(".finding-item").forEach((item) => {
    item.addEventListener("click", () => {
      const finding = findings[Number(item.dataset.index)];
      state.atlasSelection = null;
      state.attackSelection = null;
      showFinding(finding);
      if (finding.aws_uid && state.cy) {
        const node = state.cy.getElementById(finding.aws_uid);
        if (node.length) {
          state.cy.elements().unselect();
          node.select();
          if (state.viewMode === "graph") {
            state.cy.animate({ center: { eles: node }, zoom: Math.max(state.cy.zoom(), 1.1) }, { duration: 250 });
          }
        }
      }
    });
  });
}

function showEmptySelection() {
  $("#selection").className = "empty";
  $("#selection").textContent = "No selection";
}

function clearSelection() {
  state.selection = null;
  state.selectedFinding = null;
  state.selectedNodeId = null;
  state.atlasSelection = null;
  state.attackSelection = null;
  if (state.cy) state.cy.elements().unselect();
  showEmptySelection();
  if (state.focusMode === "blast") applyFilters();
  else renderCurrentView();
}

function showNode(data) {
  state.selection = { type: "resource", data };
  state.selectedNodeId = data.id;
  state.selectedFinding = null;
  state.atlasSelection = null;
  state.attackSelection = null;
  $("#selection").className = "";
  $("#selection").innerHTML = `
    <div class="selected-title">${escapeHtml(data.label)}</div>
    <div class="selected-meta">${escapeHtml(data.id)} ${copyButton(data.id)}</div>
    <div class="kv">
      ${kv("provider", data.provider || "n/a")}
      ${kv("service", data.service)}
      ${kv("type", data.resourceType)}
      ${kv("region", data.region)}
      ${kv("namespace", data.namespace || "n/a")}
      ${kv("environment", data.environment || "n/a")}
      ${kv("application", data.application || "n/a")}
      ${kv("owner", data.owner || "n/a")}
      ${kv("terraform", data.terraformAddress || "unmanaged", data.terraformAddress)}
      ${kv("finding", (data.findingTypes || []).join(", ") || "none")}
      ${kv("arn", data.arn || "n/a", data.arn)}
    </div>
    ${providerInspector(data)}
    ${jsonDetails("Tags", data.tags)}
    ${jsonDetails("Attributes", data.attributes)}
    ${jsonDetails("Evidence", data.evidence)}
    ${jsonDetails("Raw", data.raw)}
  `;
  if (state.focusMode === "blast") applyFilters();
  else renderCurrentView();
}

function showEdge(data) {
  const source = nodeById(data.source);
  const target = nodeById(data.target);
  state.selection = { type: "relationship", data };
  state.selectedFinding = null;
  state.selectedNodeId = null;
  state.atlasSelection = null;
  state.attackSelection = null;
  $("#selection").className = "";
  $("#selection").innerHTML = `
    <div class="selected-title">${escapeHtml(data.relationshipType)}</div>
    <div class="selected-meta">${escapeHtml(data.id)} ${copyButton(data.id)}</div>
    <div class="kv">
      ${kv("from", source?.label || data.source, data.source)}
      ${kv("to", target?.label || data.target, data.target)}
      ${kv("type", data.relationshipType)}
    </div>
    ${jsonDetails("Attributes", data.attributes)}
    ${jsonDetails("Evidence", data.evidence)}
  `;
  renderCurrentView();
}

function showFinding(finding) {
  state.selection = { type: "finding", data: finding };
  state.selectedFinding = finding;
  state.selectedNodeId = finding.aws_uid || null;
  state.atlasSelection = null;
  state.attackSelection = null;
  $("#selection").className = "";
  $("#selection").innerHTML = `
    <span class="severity-dot large ${escapeHtml(finding.severity)}" title="${escapeHtml(finding.severity)}" aria-label="${escapeHtml(finding.severity)}"></span>
    <div class="selected-title">${escapeHtml(finding.finding_type)}</div>
    <div class="selected-meta">${escapeHtml(finding.reason)} ${copyButton(finding.id)}</div>
    <div class="kv">
      ${kv("resource", finding.aws_uid || "n/a", finding.aws_uid)}
      ${kv("terraform", finding.terraform_address || "n/a", finding.terraform_address)}
      ${kv("blast", (finding.blast_radius || []).join(", ") || "none")}
      ${kv("action", finding.recommended_action)}
    </div>
    ${jsonDetails("Evidence", finding.evidence)}
    ${jsonDetails("Attributes", finding.attributes)}
  `;
  if (state.focusMode === "blast") applyFilters();
  else renderCurrentView();
}

function providerInspector(data) {
  if (data.provider === "k8s") return k8sInspector(data);
  if (data.provider === "aws" || data.arn) return awsInspector(data);
  return "";
}

function awsInspector(data) {
  const ingress = Array.isArray(data.attributes?.ingress) ? data.attributes.ingress : [];
  const attachedPolicies = data.attributes?.attached_policies || connectedPolicyLabels(data.id);
  const publicAccessBlock = data.attributes?.public_access_block;
  const rows = [
    kv("account", data.accountId || "n/a"),
    kv("arn", data.arn || "n/a", data.arn),
    kv("terraform", data.terraformAddress || "unmanaged", data.terraformAddress),
  ];
  if (ingress.length) rows.push(kv("ingress", `${ingress.length} rule${ingress.length === 1 ? "" : "s"}`));
  if (attachedPolicies?.length) rows.push(kv("policies", attachedPolicies.join(", ")));
  if (hasJsonValue(publicAccessBlock)) rows.push(kv("public block", compactBooleanObject(publicAccessBlock)));
  return inspectorPanel("AWS", `
    <div class="kv compact">${rows.join("")}</div>
    ${ingress.length ? objectList("Ingress", ingress.map(formatIngressRule)) : ""}
    ${jsonDetails("Public access block", publicAccessBlock)}
  `);
}

function k8sInspector(data) {
  const attributes = data.attributes || {};
  const pod = attributes.template || attributes;
  const containers = Array.isArray(pod.containers) ? pod.containers : [];
  const mounts = Array.isArray(pod.mounts) ? pod.mounts : [];
  const ownerRefs = Array.isArray(attributes.owner_references) ? attributes.owner_references : [];
  const backendServices = Array.isArray(attributes.backend_services) ? attributes.backend_services : [];
  const rules = Array.isArray(attributes.rules) ? attributes.rules : [];
  const subjects = Array.isArray(attributes.subjects) ? attributes.subjects : [];
  const roleRef = attributes.role_ref;

  return inspectorPanel("Kubernetes", `
    <div class="kv compact">
      ${kv("cluster", data.accountId || "n/a")}
      ${kv("namespace", data.namespace || "cluster")}
      ${kv("kind", attributes.kind || data.resourceType)}
      ${kv("service acct", pod.service_account || attributes.service_account || "n/a")}
      ${kv("host access", hostAccessLabel(pod))}
    </div>
    ${ownerRefs.length ? objectList("Owner refs", ownerRefs.map((owner) => `${owner.kind || "owner"} ${owner.name || ""}`.trim())) : ""}
    ${containers.length ? objectList("Containers", containers.map(formatContainer)) : ""}
    ${mounts.length ? objectList("Mounts", mounts.map(formatMount)) : ""}
    ${backendServices.length ? objectList("Ingress backends", backendServices) : ""}
    ${roleRef ? objectList("Role ref", [`${roleRef.kind || "Role"} ${roleRef.name || ""}`.trim()]) : ""}
    ${subjects.length ? objectList("Subjects", subjects.map(formatSubject)) : ""}
    ${rules.length ? jsonDetails("RBAC rules", rules) : ""}
  `);
}

function inspectorPanel(title, content) {
  return `
    <section class="provider-panel">
      <div class="provider-panel-title">${escapeHtml(title)}</div>
      ${content}
    </section>
  `;
}

function objectList(title, values) {
  const filtered = values.filter(Boolean);
  if (!filtered.length) return "";
  return `
    <div class="object-list">
      <div class="object-list-title">${escapeHtml(title)}</div>
      ${filtered.slice(0, 8).map((value) => `<span>${escapeHtml(String(value))}</span>`).join("")}
      ${filtered.length > 8 ? `<span>+${filtered.length - 8} more</span>` : ""}
    </div>
  `;
}

function connectedPolicyLabels(uid) {
  const edges = (state.graph?.edges || []).filter((edge) => {
    return edge.data.source === uid && edge.data.relationshipType === "has_attached_policy";
  });
  return edges
    .map((edge) => nodeById(edge.data.target))
    .filter(Boolean)
    .map((node) => node.label || node.id);
}

function formatIngressRule(rule) {
  const protocol = rule.ip_protocol || rule.protocol || "tcp";
  const from = rule.from_port ?? rule.fromPort ?? "";
  const to = rule.to_port ?? rule.toPort ?? "";
  const ports = from === to ? from : `${from}-${to}`;
  const ipv4 = Array.isArray(rule.ipv4_ranges) ? rule.ipv4_ranges.join(", ") : "";
  const ipv6 = Array.isArray(rule.ipv6_ranges) ? rule.ipv6_ranges.join(", ") : "";
  return `${protocol} ${ports || "all"} ${[ipv4, ipv6].filter(Boolean).join(", ")}`;
}

function compactBooleanObject(value) {
  if (!value || typeof value !== "object") return String(value);
  return Object.entries(value)
    .map(([key, item]) => `${key}:${item ? "yes" : "no"}`)
    .join(" ");
}

function hostAccessLabel(pod) {
  const values = [];
  if (pod.host_network) values.push("network");
  if (pod.host_pid) values.push("pid");
  if (pod.host_ipc) values.push("ipc");
  return values.join(", ") || "none";
}

function formatContainer(container) {
  const name = container.name || "container";
  const image = container.image ? ` ${container.image}` : "";
  const privileged = container.security_context?.privileged ? " privileged" : "";
  return `${name}${image}${privileged}`;
}

function formatMount(mount) {
  return `${mount.kind || "Object"} ${mount.name || ""} (${mount.source || "ref"})`;
}

function formatSubject(subject) {
  return `${subject.kind || "Subject"} ${subject.namespace ? `${subject.namespace}/` : ""}${subject.name || ""}`;
}

function kv(key, value, copyValue = null) {
  const copy = copyValue ? copyButton(copyValue) : "";
  return `<div><span>${escapeHtml(key)}</span><span><span class="kv-value">${escapeHtml(String(value))}</span>${copy}</span></div>`;
}

function copyButton(value) {
  if (!value) return "";
  return `<button class="copy-button" type="button" data-copy="${escapeHtml(String(value))}" title="Copy" aria-label="Copy"><svg class="icon" aria-hidden="true"><use href="#icon-copy"></use></svg></button>`;
}

function jsonDetails(title, value) {
  if (!hasJsonValue(value)) return "";
  return `
    <details class="json-details">
      <summary>${escapeHtml(title)}</summary>
      <pre>${escapeHtml(JSON.stringify(value, null, 2))}</pre>
    </details>
  `;
}

function hasJsonValue(value) {
  if (value === null || value === undefined) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

function emptyState(title, detail) {
  return `<div class="empty"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span></div>`;
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
  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function shortText(value, maxLength) {
  const text = String(value);
  if (text.length <= maxLength) return text;
  return `${text.slice(0, Math.max(0, maxLength - 3))}...`;
}

function setFocusMode(mode) {
  state.focusMode = FOCUS_MODES.includes(mode) ? mode : "all";
  syncModeControls();
  applyFilters();
  updateUrlFromFilters();
}

function syncModeControls() {
  document.querySelectorAll(".mode-button[data-mode]").forEach((button) => {
    button.classList.toggle("active", button.dataset.mode === state.focusMode);
  });
  syncModeCycle();
}

function syncModeCycle() {
  const button = $("#mode-cycle");
  if (!button) return;
  const meta = FOCUS_MODE_META[state.focusMode] || FOCUS_MODE_META.all;
  button.title = meta.label;
  button.setAttribute("aria-label", meta.label);
  button.innerHTML = iconSvg(meta.icon);
  button.classList.toggle("active", state.focusMode !== "all");
}

function cycleFocusMode() {
  const index = FOCUS_MODES.indexOf(state.focusMode);
  const next = FOCUS_MODES[(Math.max(0, index) + 1) % FOCUS_MODES.length];
  setFocusMode(next);
}

function setViewMode(mode) {
  state.viewMode = VIEW_MODES.includes(mode) ? mode : "graph";
  syncViewControls();
  renderCurrentView();
  updateUrlFromFilters();
}

function syncViewControls() {
  document.querySelectorAll(".view-button[data-view]").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === state.viewMode);
  });
}

function cycleViewMode() {
  const index = VIEW_MODES.indexOf(state.viewMode);
  const next = VIEW_MODES[(Math.max(0, index) + 1) % VIEW_MODES.length];
  setViewMode(next);
}

function loadThemePreference() {
  try {
    const theme = localStorage.getItem(THEME_STORAGE_KEY);
    return theme === "light" || theme === "dark" ? theme : "light";
  } catch {
    return "light";
  }
}

function setTheme(theme, persist = true) {
  state.theme = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = state.theme;
  if (persist) {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, state.theme);
    } catch {
      // Ignore storage failures; the toggle should still work for this session.
    }
  }
  syncThemeToggle();
  applyThemeToGraph();
  renderCurrentView();
}

function toggleTheme() {
  setTheme(state.theme === "dark" ? "light" : "dark");
}

function syncThemeToggle() {
  const button = $("#theme-toggle");
  if (!button) return;
  const dark = state.theme === "dark";
  const label = dark ? "Light theme" : "Dark theme";
  button.title = label;
  button.setAttribute("aria-label", label);
  button.innerHTML = iconSvg(dark ? "icon-sun" : "icon-moon");
  button.classList.toggle("active", !dark);
}

function applyThemeToGraph() {
  if (!state.cy || !state.graph?.nodes?.length) return;
  const selection = state.selection;
  renderGraph(state.graph);
  restoreSelection(selection);
}

function togglePanel(panel) {
  setPanelVisibility(panel, !state.panels[panel]);
}

function setPanelVisibility(panel, visible, options = {}) {
  if (!Object.prototype.hasOwnProperty.call(state.panels, panel)) return;
  const updateUrl = options.updateUrl !== false;
  state.panels[panel] = Boolean(visible);
  syncPanelLayout();
  if (updateUrl) updateUrlFromFilters();
}

function syncPanelLayout(options = {}) {
  const workspace = $(".workspace");
  if (!workspace) return;
  workspace.classList.toggle("hide-inspector", !state.panels.inspector);
  workspace.classList.toggle("hide-findings", !state.panels.findings);
  syncPanelControls();
  if (options.refresh !== false) refreshGraphViewport();
}

function syncPanelControls() {
  syncPanelButton("toggle-inspector", state.panels.inspector, "inspector");
  syncPanelButton("toggle-findings", state.panels.findings, "findings");
}

function syncPanelButton(id, visible, label) {
  const button = $(`#${id}`);
  if (!button) return;
  const action = visible ? "Hide" : "Show";
  const title = `${action} ${label}`;
  button.title = title;
  button.setAttribute("aria-label", title);
  button.setAttribute("aria-pressed", visible ? "true" : "false");
  button.classList.toggle("active", visible);
}

function refreshGraphViewport() {
  requestAnimationFrame(() => {
    if (!state.graph) return;
    if (state.viewMode === "graph" && state.cy) {
      state.cy.resize();
      state.cy.fit(undefined, 45);
    } else {
      renderCurrentView();
    }
  });
}

function restoreSelection(selection) {
  if (!selection) return;
  if (selection.type === "resource") {
    showNode(selection.data);
    const node = state.cy?.getElementById(selection.data.id);
    if (node?.length) node.select();
  } else if (selection.type === "relationship") {
    showEdge(selection.data);
  } else if (selection.type === "finding") {
    showFinding(selection.data);
  } else if (selection.type === "exposure") {
    showExposureSelection(selection.data);
  } else if (selection.type === "attack") {
    selectGraphNodesByIds(selection.data.resourceIds || []);
    showAttackSelection(selection.data);
  } else if (selection.type === "group") {
    selectGraphNodesByIds(selection.data.nodeIds || []);
    showGroupSelection(selection.data);
  }
}

function spreadGraph() {
  if (!state.cy) return;
  if (state.viewMode !== "graph") {
    state.viewMode = "graph";
    syncViewControls();
    renderCurrentView();
  }
  state.cy.layout({
    name: "cose",
    animate: true,
    animationDuration: 650,
    fit: true,
    padding: 64,
    nodeRepulsion: 26000,
    idealEdgeLength: 215,
    edgeElasticity: 0.08,
    nodeOverlap: 30,
    componentSpacing: 150,
    gravity: 0.18,
    numIter: 900,
  }).run();
}

function setSpreadMode(enabled, options = {}) {
  const layout = options.layout !== false;
  const updateUrl = options.updateUrl !== false;
  state.spreadMode = Boolean(enabled);
  document.body.classList.toggle("spread-mode", state.spreadMode);
  syncSpreadControl();
  applySpreadClasses();
  if (state.spreadMode && layout) {
    spreadGraph();
  } else if (!state.spreadMode && layout && state.cy) {
    runLayout($("#layout")?.value || "cose");
  }
  if (updateUrl) updateUrlFromFilters();
}

function toggleSpreadMode() {
  setSpreadMode(!state.spreadMode);
}

function syncSpreadControl() {
  const button = $("#spread");
  if (!button) return;
  button.classList.toggle("active", state.spreadMode);
  button.title = state.spreadMode ? "Compact graph" : "Spread graph";
  button.setAttribute("aria-label", button.title);
}

function applySpreadClasses() {
  if (!state.cy) {
    syncSpreadControl();
    return;
  }
  const elements = state.cy.elements();
  elements.removeClass("spread spread-focus spread-dim");
  syncSpreadControl();
  if (!state.spreadMode) return;

  elements.addClass("spread");
  const focusIds = spreadFocusIds();
  if (!focusIds.size) return;

  state.cy.nodes().forEach((node) => {
    node.toggleClass("spread-focus", focusIds.has(node.id()));
    node.toggleClass("spread-dim", !focusIds.has(node.id()));
  });
  state.cy.edges().forEach((edge) => {
    const inFocus = focusIds.has(edge.source().id()) && focusIds.has(edge.target().id());
    edge.toggleClass("spread-focus", inFocus);
    edge.toggleClass("spread-dim", !inFocus);
  });
}

function spreadFocusIds() {
  const ids = new Set();
  if (!state.cy) return ids;

  if (state.selectedFinding) {
    if (state.selectedFinding.aws_uid) ids.add(state.selectedFinding.aws_uid);
    for (const uid of state.selectedFinding.blast_radius || []) ids.add(uid);
    return ids;
  }

  if (state.selection?.type === "relationship") {
    ids.add(state.selection.data.source);
    ids.add(state.selection.data.target);
    return ids;
  }

  if (!state.selectedNodeId) return ids;
  ids.add(state.selectedNodeId);
  let frontier = new Set([state.selectedNodeId]);
  for (let depth = 0; depth < 2; depth += 1) {
    const next = new Set();
    for (const id of frontier) {
      const node = state.cy.getElementById(id);
      if (!node.length) continue;
      node.connectedEdges().forEach((edge) => {
        const source = edge.source().id();
        const target = edge.target().id();
        if (!ids.has(source)) next.add(source);
        if (!ids.has(target)) next.add(target);
        ids.add(source);
        ids.add(target);
      });
    }
    frontier = next;
  }
  return ids;
}

function fitGraph() {
  if (state.viewMode !== "graph") {
    renderCurrentView();
    return;
  }
  if (state.cy) state.cy.fit(undefined, 45);
}

function resetView() {
  state.filters = defaultFilters();
  state.focusMode = "all";
  state.spreadMode = false;
  state.atlasSelection = null;
  state.attackSelection = null;
  clearSelection();
  syncControlsFromState();
  syncSpreadControl();
  applyFilters();
  updateUrlFromFilters();
  fitGraph();
}

function iconSvg(id) {
  return `<svg class="icon" aria-hidden="true"><use href="#${id}"></use></svg>`;
}

function applyFilterUpdate(update) {
  update();
  syncControlsFromState();
  applyFilters();
  updateUrlFromFilters();
}

function setFilter(key, value) {
  applyFilterUpdate(() => {
    state.filters[key] = value;
  });
}

function toggleFilter(key) {
  applyFilterUpdate(() => {
    state.filters[key] = !state.filters[key];
  });
}

function setLayout(value) {
  const select = $("#layout");
  if (select) select.value = value;
  if (state.spreadMode) setSpreadMode(false, { layout: false, updateUrl: false });
  runLayout(value);
}

function selectOptionCommands(selector, label, icon, apply) {
  const select = $(selector);
  if (!select) return [];
  return [...select.options]
    .filter((option) => option.value)
    .map((option) => ({
      id: `${selector.slice(1)}-${commandSlug(option.value)}`,
      label: `${label}: ${option.textContent}`,
      hint: "",
      icon,
      run: () => apply(option.value),
    }));
}

function commandSlug(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "value";
}

function commandList() {
  return [
    ...FOCUS_MODES.map((mode) => ({
      id: `mode-${mode}`,
      label: FOCUS_MODE_META[mode].label,
      hint: FOCUS_MODE_META[mode].hint,
      icon: FOCUS_MODE_META[mode].icon,
      run: () => setFocusMode(mode),
    })),
    ...VIEW_MODES.map((mode) => ({
      id: `view-${mode}`,
      label: `View: ${VIEW_MODE_META[mode].label}`,
      hint: VIEW_MODE_META[mode].hint,
      icon: VIEW_MODE_META[mode].icon,
      run: () => setViewMode(mode),
    })),
    { id: "severity-critical", label: "Severity: Critical", hint: "", icon: "icon-risk", run: () => setFilter("severity", "critical") },
    { id: "severity-high", label: "Severity: High", hint: "", icon: "icon-risk", run: () => setFilter("severity", "high") },
    { id: "severity-medium", label: "Severity: Medium", hint: "", icon: "icon-finding", run: () => setFilter("severity", "medium") },
    { id: "severity-none", label: "Severity: No finding", hint: "", icon: "icon-all", run: () => setFilter("severity", "none") },
    ...selectOptionCommands("#service", "Service", "icon-resource", (value) => setFilter("service", value)),
    ...selectOptionCommands("#provider", "Provider", "icon-all", (value) => setFilter("provider", value)),
    ...selectOptionCommands("#namespace", "Namespace", "icon-atlas", (value) => setFilter("namespace", value)),
    ...selectOptionCommands("#environment", "Environment", "icon-finding", (value) => setFilter("environment", value)),
    ...selectOptionCommands("#application", "Application", "icon-relation", (value) => setFilter("application", value)),
    ...selectOptionCommands("#owner", "Owner", "icon-agent", (value) => setFilter("owner", value)),
    ...Object.entries(GROUP_FIELDS).map(([key, meta]) => ({
      id: `group-${key}`,
      label: `Group by: ${meta.label}`,
      hint: key === "environment" ? "L" : "",
      icon: "icon-all",
      run: () => {
        state.groupBy = key;
        if (state.viewMode === "groups") {
          renderCurrentView();
          updateUrlFromFilters();
        } else {
          setViewMode("groups");
        }
      },
    })),
    { id: "findings-only", label: state.filters.findingsOnly ? "All resources" : "Findings only", hint: "", icon: "icon-finding", run: () => toggleFilter("findingsOnly") },
    { id: "terraform-only", label: state.filters.managedOnly ? "All management states" : "Terraform only", hint: "", icon: "icon-managed", run: () => toggleFilter("managedOnly") },
    { id: "layout-layers", label: "Layout: Layers", hint: "", icon: "icon-relation", run: () => setLayout("breadthfirst") },
    { id: "layout-force", label: "Layout: Force", hint: "", icon: "icon-relation", run: () => setLayout("cose") },
    { id: "layout-circle", label: "Layout: Circle", hint: "", icon: "icon-relation", run: () => setLayout("circle") },
    { id: "panel-inspector", label: state.panels.inspector ? "Hide inspector" : "Show inspector", hint: "[", icon: "icon-panel-left", run: () => togglePanel("inspector") },
    { id: "panel-findings", label: state.panels.findings ? "Hide findings" : "Show findings", hint: "]", icon: "icon-panel-right", run: () => togglePanel("findings") },
    { id: "spread", label: state.spreadMode ? "Compact graph" : "Spread graph", hint: "S", icon: "icon-spread", run: toggleSpreadMode },
    { id: "fit", label: "Fit graph", hint: "F", icon: "icon-fit", run: fitGraph },
    { id: "reset", label: "Clear filters", hint: "R", icon: "icon-reset", run: resetView },
    { id: "search", label: "Search", hint: "/", icon: "icon-search", run: () => $("#search").focus() },
    { id: "theme", label: state.theme === "dark" ? "Light theme" : "Dark theme", hint: "T", icon: state.theme === "dark" ? "icon-sun" : "icon-moon", run: toggleTheme },
    { id: "agent", label: "Copy agent context", hint: "A", icon: "icon-agent", run: copyAgentContext },
  ];
}

function openPalette() {
  state.palette.open = true;
  state.palette.index = 0;
  $("#palette").hidden = false;
  $("#palette-input").value = "";
  renderPalette();
  requestAnimationFrame(() => $("#palette-input").focus());
}

function closePalette() {
  state.palette.open = false;
  $("#palette").hidden = true;
}

function renderPalette() {
  const query = $("#palette-input").value.trim().toLowerCase();
  state.palette.filtered = commandList().filter((command) => {
    return !query || `${command.label} ${command.hint}`.toLowerCase().includes(query);
  });
  if (state.palette.index >= state.palette.filtered.length) state.palette.index = 0;
  $("#palette-list").innerHTML = state.palette.filtered.map((command, index) => {
    const active = index === state.palette.index ? " active" : "";
    return `
      <button class="palette-item${active}" type="button" data-command="${escapeHtml(command.id)}">
        ${iconSvg(command.icon)}
        <span>${escapeHtml(command.label)}</span>
        <small>${escapeHtml(command.hint)}</small>
      </button>
    `;
  }).join("");
}

function runPaletteCommand(commandId = null) {
  const command = commandId
    ? commandList().find((item) => item.id === commandId)
    : state.palette.filtered[state.palette.index];
  if (!command) return;
  closePalette();
  command.run();
}

function visibleNodeData() {
  if (!state.cy) return [];
  return state.cy.nodes().filter((node) => node.visible()).map((node) => compactNode(node.data()));
}

function visibleEdgeData() {
  if (!state.cy) return [];
  return state.cy.edges().filter((edge) => edge.visible()).map((edge) => {
    const data = edge.data();
    return {
      id: data.id,
      source: data.source,
      target: data.target,
      type: data.relationshipType,
    };
  });
}

function compactNode(data) {
  return {
    uid: data.id,
    label: data.label,
    provider: data.provider || null,
    account_id: data.accountId || null,
    partition: data.partition || null,
    service: data.service,
    type: data.resourceType,
    region: data.region,
    namespace: data.namespace || null,
    arn: data.arn || null,
    environment: data.environment || null,
    application: data.application || null,
    owner: data.owner || null,
    terraform_address: data.terraformAddress || null,
    severity: data.severity || null,
    finding_types: data.findingTypes || [],
  };
}

function compactFinding(finding) {
  return {
    id: finding.id,
    type: finding.finding_type,
    severity: finding.severity,
    aws_uid: finding.aws_uid || null,
    terraform_address: finding.terraform_address || null,
    reason: finding.reason,
    recommended_action: finding.recommended_action,
    blast_radius: finding.blast_radius || [],
  };
}

function compactSelection() {
  if (!state.selection) return null;
  if (state.selection.type === "finding") {
    return { type: "finding", finding: compactFinding(state.selection.data) };
  }
  if (state.selection.type === "resource") {
    return { type: "resource", resource: compactNode(state.selection.data) };
  }
  if (state.selection.type === "relationship") {
    const data = state.selection.data;
    return {
      type: "relationship",
      relationship: {
        id: data.id,
        source: data.source,
        target: data.target,
        type: data.relationshipType,
      },
    };
  }
  if (state.selection.type === "exposure") {
    const cell = state.selection.data;
    return {
      type: "exposure",
      exposure: {
        application: cell.applicationValue,
        environment: cell.environmentValue,
        resources: cell.resources,
        terraform_managed: cell.managed,
        findings: cell.findings.length,
        public_ingress: cell.publicIngress,
        blast_radius: cell.blastRadius,
        services: cell.services,
        owners: cell.owners,
      },
    };
  }
  if (state.selection.type === "attack") {
    const node = state.selection.data;
    return {
      type: "attack",
      attack: {
        layer: node.layer,
        kind: node.kind,
        label: node.label,
        detail: node.detail,
        severity: node.severity,
        resources: node.resourceIds,
        findings: node.findings.map(compactFinding),
        application: node.application,
        environment: node.environment,
        owner: node.owner,
      },
    };
  }
  if (state.selection.type === "group") {
    const group = state.selection.data;
    return {
      type: "group",
      group: {
        group_by: group.groupBy,
        value: group.value,
        label: group.label,
        resources: group.resources,
        relationships: group.relationships,
        severity: group.maxSeverity,
        findings: group.findings.length,
        providers: group.providers,
        namespaces: group.namespaces,
        applications: group.applications,
        owners: group.owners,
        relationship_types: group.relationshipTypes,
      },
    };
  }
  return { type: state.selection.type };
}

function agentContext() {
  const visibleNodes = visibleNodeData();
  const visibleIds = new Set(visibleNodes.map((node) => node.uid));
  const findings = state.selectedFinding
    ? [state.selectedFinding]
    : state.findings.filter((finding) => {
        if (finding.aws_uid && visibleIds.has(finding.aws_uid)) return true;
        return (finding.blast_radius || []).some((uid) => visibleIds.has(uid));
      });
  return {
    schema_version: "cloudmapper.ui.agent-context.v1",
    generated_at: new Date().toISOString(),
    view: state.viewMode,
    mode: state.focusMode,
    filters: state.filters,
    selection: compactSelection(),
    summary: state.graph?.summary || null,
    resources: visibleNodes,
    relationships: visibleEdgeData(),
    findings: findings.map(compactFinding),
  };
}

async function copyAgentContext() {
  const payload = agentContext();
  const text = [
    "Use this Cloudmapper context to reason about infrastructure drift and risk. Prioritize unmanaged risky resources, blast radius, evidence, and concrete remediation actions.",
    "",
    JSON.stringify(payload, null, 2),
  ].join("\n");
  await copyText(text);
  const button = $("#agent-copy");
  if (button) {
    const originalTitle = button.title;
    button.title = "Copied";
    button.classList.add("copied");
    setTimeout(() => {
      button.title = originalTitle;
      button.classList.remove("copied");
    }, 900);
  }
}

function bindControls() {
  $("#search").addEventListener("input", (event) => {
    state.filters.search = event.target.value;
    applyFilters();
    updateUrlFromFilters();
  });
  $("#severity").addEventListener("change", (event) => {
    state.filters.severity = event.target.value;
    applyFilters();
    updateUrlFromFilters();
  });
  $("#service").addEventListener("change", (event) => {
    state.filters.service = event.target.value;
    applyFilters();
    updateUrlFromFilters();
  });
  $("#provider").addEventListener("change", (event) => {
    state.filters.provider = event.target.value;
    applyFilters();
    updateUrlFromFilters();
  });
  $("#namespace").addEventListener("change", (event) => {
    state.filters.namespace = event.target.value;
    applyFilters();
    updateUrlFromFilters();
  });
  $("#environment").addEventListener("change", (event) => {
    state.filters.environment = event.target.value;
    applyFilters();
    updateUrlFromFilters();
  });
  $("#application").addEventListener("change", (event) => {
    state.filters.application = event.target.value;
    applyFilters();
    updateUrlFromFilters();
  });
  $("#owner").addEventListener("change", (event) => {
    state.filters.owner = event.target.value;
    applyFilters();
    updateUrlFromFilters();
  });
  $("#findings-only").addEventListener("change", (event) => {
    state.filters.findingsOnly = event.target.checked;
    applyFilters();
    updateUrlFromFilters();
  });
  $("#managed-only").addEventListener("change", (event) => {
    state.filters.managedOnly = event.target.checked;
    applyFilters();
    updateUrlFromFilters();
  });
  document.querySelectorAll(".mode-button[data-mode]").forEach((button) => {
    button.addEventListener("click", () => setFocusMode(button.dataset.mode));
  });
  document.querySelectorAll(".view-button[data-view]").forEach((button) => {
    button.addEventListener("click", () => setViewMode(button.dataset.view));
  });
  $("#mode-cycle").addEventListener("click", cycleFocusMode);
  $("#toggle-inspector").addEventListener("click", () => togglePanel("inspector"));
  $("#toggle-findings").addEventListener("click", () => togglePanel("findings"));
  $("#layout").addEventListener("change", (event) => runLayout(event.target.value));
  $("#fit").addEventListener("click", fitGraph);
  $("#spread").addEventListener("click", toggleSpreadMode);
  $("#reset")?.addEventListener("click", resetView);
  $("#agent-copy").addEventListener("click", copyAgentContext);
  $("#theme-toggle").addEventListener("click", toggleTheme);
  $("#palette-open").addEventListener("click", openPalette);
  $("#palette-input").addEventListener("input", () => {
    state.palette.index = 0;
    renderPalette();
  });
  $("#palette-list").addEventListener("click", (event) => {
    const item = event.target.closest("[data-command]");
    if (!item) return;
    runPaletteCommand(item.dataset.command);
  });
  $("#palette").addEventListener("click", (event) => {
    if (event.target === $("#palette")) closePalette();
  });
  document.addEventListener("keydown", handleKeyboard);
  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy]");
    if (!button) return;
    await copyText(button.dataset.copy || "");
    const originalTitle = button.title;
    button.title = "Copied";
    button.classList.add("copied");
    setTimeout(() => {
      button.title = originalTitle;
      button.classList.remove("copied");
    }, 900);
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest(".risk-chip");
    if (!button) return;
    applyChipFilter(button.dataset);
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-reset-view]");
    if (!button) return;
    resetView();
  });
}

function defaultFilters() {
  return {
    search: "",
    severity: "",
    service: "",
    environment: "",
    application: "",
    provider: "",
    namespace: "",
    owner: "",
    findingsOnly: false,
    managedOnly: false,
  };
}

function applyChipFilter(dataset) {
  state.atlasSelection = null;
  state.attackSelection = null;
  if (dataset.filterSeverity) state.filters.severity = dataset.filterSeverity;
  if (dataset.filterService) state.filters.service = dataset.filterService;
  if (dataset.filterProvider) state.filters.provider = dataset.filterProvider;
  if (dataset.filterNamespace) state.filters.namespace = dataset.filterNamespace;
  if (dataset.filterEnvironment) state.filters.environment = dataset.filterEnvironment;
  if (dataset.filterApplication) state.filters.application = dataset.filterApplication;
  if (dataset.filterOwner) state.filters.owner = dataset.filterOwner;
  syncControlsFromState();
  applyFilters();
  updateUrlFromFilters();
}

function loadFiltersFromUrl() {
  const params = new URLSearchParams(window.location.search);
  state.filters.search = params.get("q") || "";
  state.filters.severity = params.get("severity") || "";
  state.filters.service = params.get("service") || "";
  state.filters.provider = params.get("provider") || "";
  state.filters.namespace = params.get("ns") || "";
  state.filters.environment = params.get("env") || "";
  state.filters.application = params.get("app") || "";
  state.filters.owner = params.get("owner") || "";
  state.filters.findingsOnly = params.get("findings") === "1";
  state.filters.managedOnly = params.get("managed") === "1";
  const mode = params.get("mode") || "all";
  state.focusMode = FOCUS_MODES.includes(mode) ? mode : "all";
  const view = params.get("view") || "graph";
  state.viewMode = VIEW_MODES.includes(view) ? view : "graph";
  const group = params.get("group") || "environment";
  state.groupBy = GROUP_FIELDS[group] ? group : "environment";
  state.spreadMode = params.get("spread") === "1";
  state.panels.inspector = params.get("inspector") !== "0";
  state.panels.findings = params.get("findingsPanel") !== "0";
}

function syncControlsFromState() {
  $("#search").value = state.filters.search;
  $("#severity").value = state.filters.severity;
  $("#service").value = state.filters.service;
  $("#provider").value = state.filters.provider;
  $("#namespace").value = state.filters.namespace;
  $("#environment").value = state.filters.environment;
  $("#application").value = state.filters.application;
  $("#owner").value = state.filters.owner;
  $("#findings-only").checked = state.filters.findingsOnly;
  $("#managed-only").checked = state.filters.managedOnly;
  syncModeControls();
  syncViewControls();
  syncSpreadControl();
  syncPanelLayout({ refresh: false });
}

function updateUrlFromFilters() {
  const params = new URLSearchParams();
  if (state.filters.search) params.set("q", state.filters.search);
  if (state.filters.severity) params.set("severity", state.filters.severity);
  if (state.filters.service) params.set("service", state.filters.service);
  if (state.filters.provider) params.set("provider", state.filters.provider);
  if (state.filters.namespace) params.set("ns", state.filters.namespace);
  if (state.filters.environment) params.set("env", state.filters.environment);
  if (state.filters.application) params.set("app", state.filters.application);
  if (state.filters.owner) params.set("owner", state.filters.owner);
  if (state.filters.findingsOnly) params.set("findings", "1");
  if (state.filters.managedOnly) params.set("managed", "1");
  if (state.focusMode !== "all") params.set("mode", state.focusMode);
  if (state.viewMode !== "graph") params.set("view", state.viewMode);
  if (state.groupBy !== "environment") params.set("group", state.groupBy);
  if (state.spreadMode) params.set("spread", "1");
  if (!state.panels.inspector) params.set("inspector", "0");
  if (!state.panels.findings) params.set("findingsPanel", "0");
  const query = params.toString();
  const next = query ? `${window.location.pathname}?${query}` : window.location.pathname;
  window.history.replaceState(null, "", next);
}

function handleKeyboard(event) {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    openPalette();
    return;
  }

  if (state.palette.open) {
    if (event.key === "Escape") {
      event.preventDefault();
      closePalette();
      return;
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      state.palette.index = Math.min(state.palette.index + 1, Math.max(0, state.palette.filtered.length - 1));
      renderPalette();
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      state.palette.index = Math.max(0, state.palette.index - 1);
      renderPalette();
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      runPaletteCommand();
      return;
    }
  }

  const target = event.target;
  const typing = target?.matches?.("input, textarea, select");
  if (typing) {
    if (event.key === "Escape") target.blur();
    return;
  }

  if (event.key === "/") {
    event.preventDefault();
    $("#search").focus();
  } else if (event.key === "Escape") {
    clearSelection();
  } else if (event.key.toLowerCase() === "f") {
    fitGraph();
  } else if (event.key === "[") {
    togglePanel("inspector");
  } else if (event.key === "]") {
    togglePanel("findings");
  } else if (event.key.toLowerCase() === "s") {
    toggleSpreadMode();
  } else if (event.key.toLowerCase() === "r") {
    resetView();
  } else if (event.key.toLowerCase() === "m") {
    cycleFocusMode();
  } else if (event.key.toLowerCase() === "v") {
    cycleViewMode();
  } else if (event.key.toLowerCase() === "g") {
    setViewMode("graph");
  } else if (event.key.toLowerCase() === "e") {
    setViewMode("exposure");
  } else if (event.key.toLowerCase() === "l") {
    setViewMode("groups");
  } else if (event.key.toLowerCase() === "t") {
    toggleTheme();
  } else if (event.key === "0") {
    setFocusMode("all");
  } else if (event.key === "1") {
    setFocusMode("risk");
  } else if (event.key === "2") {
    setFocusMode("unmanaged");
  } else if (event.key === "3") {
    setFocusMode("terraform");
  } else if (event.key.toLowerCase() === "b") {
    setFocusMode("blast");
  } else if (event.key.toLowerCase() === "a") {
    copyAgentContext();
  }
}

async function copyText(value) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  document.body.removeChild(textarea);
}

async function boot() {
  setTheme(loadThemePreference(), false);
  loadFiltersFromUrl();
  syncControlsFromState();
  bindControls();
  if (!window.cytoscape) {
    $("#cy").innerHTML = emptyState("Graph library failed to load", "The bundled Cytoscape asset was not served.");
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
    $("#cy").innerHTML = emptyState("Could not load map data", error.message);
    renderFindings({ run_id: null, findings: [] });
  }
}

boot();
