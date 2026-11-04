/**
 * Network Packet Analyzer - Frontend Controller
 * Sanjivani College of Engineering, Kopargaon
 */

document.addEventListener("DOMContentLoaded", () => {
  // UI Elements
  const btnStart = document.getElementById("btnStart");
  const btnStop = document.getElementById("btnStop");
  const btnClear = document.getElementById("btnClear");
  const captureModeSelect = document.getElementById("captureModeSelect");
  const interfaceSelect = document.getElementById("interfaceSelect");
  const liveStatusBadge = document.getElementById("liveStatusBadge");
  const statusText = document.getElementById("statusText");
  const alertBanner = document.getElementById("alertBanner");

  // Stat Counters
  const statTotal = document.getElementById("statTotal");
  const statTcp = document.getElementById("statTcp");
  const statUdp = document.getElementById("statUdp");
  const statDns = document.getElementById("statDns");
  const statIcmp = document.getElementById("statIcmp");
  const statBytes = document.getElementById("statBytes");

  // Progress Bar Elements
  const barTcp = document.getElementById("barTcp");
  const barUdp = document.getElementById("barUdp");
  const barDns = document.getElementById("barDns");
  const barIcmp = document.getElementById("barIcmp");
  const barOther = document.getElementById("barOther");

  // Filter Elements
  const filterProtocol = document.getElementById("filterProtocol");
  const filterSrc = document.getElementById("filterSrc");
  const filterDst = document.getElementById("filterDst");
  const btnResetFilters = document.getElementById("btnResetFilters");
  const chkAutoScroll = document.getElementById("chkAutoScroll");
  const visibleCountBadge = document.getElementById("visibleCountBadge");

  // Table Elements
  const packetTableBody = document.getElementById("packetTableBody");
  const emptyStateRow = document.getElementById("emptyStateRow");
  const tableContainer = document.querySelector(".table-container");

  // Modal Elements
  const packetModal = document.getElementById("packetModal");
  const btnModalClose = document.getElementById("btnModalClose");
  const modalProtocolBadge = document.getElementById("modalProtocolBadge");
  const modalTitle = document.getElementById("modalTitle");
  const modalLayers = document.getElementById("modalLayers");
  const modalTime = document.getElementById("modalTime");
  const modalLength = document.getElementById("modalLength");
  const modalSrc = document.getElementById("modalSrc");
  const modalDst = document.getElementById("modalDst");
  const modalSrcPort = document.getElementById("modalSrcPort");
  const modalDstPort = document.getElementById("modalDstPort");
  const modalInfo = document.getElementById("modalInfo");
  const modalPayload = document.getElementById("modalPayload");

  // Internal State
  let isCapturing = false;
  let pollTimer = null;
  let allPackets = [];
  let lastFetchedId = 0;

  // Initialize
  init();

  async function init() {
    await loadInterfaces();
    setupEventListeners();
    await checkInitialStatus();
  }

  // Load available network adapters
  async function loadInterfaces() {
    try {
      const res = await fetch("/api/interfaces");
      const data = await res.json();
      interfaceSelect.innerHTML = "";
      
      data.interfaces.forEach((iface) => {
        const opt = document.createElement("option");
        opt.value = iface.id;
        opt.textContent = iface.name;
        interfaceSelect.appendChild(opt);
      });
    } catch (err) {
      console.error("Failed to load interfaces:", err);
    }
  }

  // Check backend status on page load
  async function checkInitialStatus() {
    try {
      const res = await fetch("/api/status");
      const status = await res.json();
      if (status.running) {
        setCaptureActive(true, status.mode);
        startPolling();
      } else {
        setCaptureActive(false);
      }
      refreshStats();
      fetchPackets();
    } catch (err) {
      console.warn("Backend not yet reachable:", err);
    }
  }

  function setupEventListeners() {
    btnStart.addEventListener("click", handleStart);
    btnStop.addEventListener("click", handleStop);
    btnClear.addEventListener("click", handleClear);

    // Filters
    filterProtocol.addEventListener("change", renderFilteredTable);
    filterSrc.addEventListener("input", debounce(renderFilteredTable, 200));
    filterDst.addEventListener("input", debounce(renderFilteredTable, 200));
    btnResetFilters.addEventListener("click", () => {
      filterProtocol.value = "ALL";
      filterSrc.value = "";
      filterDst.value = "";
      renderFilteredTable();
    });

    // Modal Close
    btnModalClose.addEventListener("click", closeModal);
    packetModal.querySelector(".modal-backdrop").addEventListener("click", closeModal);
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeModal();
    });

    // Capture mode change UI adjustment
    captureModeSelect.addEventListener("change", () => {
      const isLive = captureModeSelect.value === "live";
      if (!isLive) {
        interfaceSelect.value = "demo";
      }
    });
  }

  // Handle Start Capture
  async function handleStart() {
    hideAlert();
    const mode = captureModeSelect.value;
    const iface = interfaceSelect.value;

    try {
      btnStart.disabled = true;
      const res = await fetch("/api/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: mode, interface: iface }),
      });
      const data = await res.json();

      if (data.success) {
        setCaptureActive(true, mode);
        startPolling();
      } else {
        showAlert(data.message || "Could not start packet capture");
        btnStart.disabled = false;
      }
    } catch (err) {
      showAlert("Network connection error: " + err.message);
      btnStart.disabled = false;
    }
  }

  // Handle Stop Capture
  async function handleStop() {
    try {
      btnStop.disabled = true;
      const res = await fetch("/api/stop", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        setCaptureActive(false);
        stopPolling();
      }
    } catch (err) {
      console.error("Error stopping capture:", err);
    }
  }

  // Handle Clear
  async function handleClear() {
    try {
      await fetch("/api/clear", { method: "POST" });
      allPackets = [];
      lastFetchedId = 0;
      packetTableBody.innerHTML = "";
      if (emptyStateRow) {
        packetTableBody.appendChild(emptyStateRow);
        emptyStateRow.style.display = "";
      }
      refreshStats();
      updateVisibleCount(0);
    } catch (err) {
      console.error("Error clearing packets:", err);
    }
  }

  // Polling loop
  function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(pollStep, 800);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  async function pollStep() {
    try {
      await Promise.all([refreshStats(), fetchDeltaPackets(), checkBackendStatus()]);
    } catch (err) {
      console.error("Polling error:", err);
    }
  }

  async function checkBackendStatus() {
    const res = await fetch("/api/status");
    const status = await res.json();
    if (!status.running && isCapturing) {
      setCaptureActive(false);
      stopPolling();
      if (status.error) {
        showAlert("Live capture stopped: " + status.error + " (Tip: Use Demo Mode for safe demonstration without admin rights)");
      }
    }
  }

  // Fetch only newly added packets using since_id
  async function fetchDeltaPackets() {
    try {
      const url = `/api/packets?since_id=${lastFetchedId}&limit=100`;
      const res = await fetch(url);
      const data = await res.json();

      if (data.packets && data.packets.length > 0) {
        const newPackets = data.packets;
        newPackets.forEach((pkt) => {
          allPackets.push(pkt);
          if (pkt.id > lastFetchedId) {
            lastFetchedId = pkt.id;
          }
        });

        // Hide empty state row if present
        if (emptyStateRow) {
          emptyStateRow.style.display = "none";
        }

        // Append to table if packet matches current filters
        const frag = document.createDocumentFragment();
        newPackets.forEach((pkt) => {
          if (packetMatchesFilter(pkt)) {
            const tr = createPacketRow(pkt);
            frag.appendChild(tr);
          }
        });

        if (frag.children.length > 0) {
          packetTableBody.appendChild(frag);
          if (chkAutoScroll.checked) {
            tableContainer.scrollTop = tableContainer.scrollHeight;
          }
        }

        updateVisibleCount(packetTableBody.querySelectorAll(".packet-row").length);
      }
    } catch (err) {
      console.error("Fetch delta error:", err);
    }
  }

  // Fetch all packets (used on reset / filter change)
  async function fetchPackets() {
    try {
      const res = await fetch("/api/packets?limit=300");
      const data = await res.json();
      allPackets = data.packets || [];
      if (allPackets.length > 0) {
        lastFetchedId = allPackets[allPackets.length - 1].id;
      }
      renderFilteredTable();
    } catch (err) {
      console.error("Error fetching packets:", err);
    }
  }

  // Filter matching
  function packetMatchesFilter(pkt) {
    const protoVal = filterProtocol.value.toUpperCase();
    const srcVal = filterSrc.value.trim().toLowerCase();
    const dstVal = filterDst.value.trim().toLowerCase();

    if (protoVal !== "ALL") {
      if (protoVal === "HTTP" && pkt.protocol !== "HTTP") return false;
      if (protoVal !== "HTTP" && pkt.protocol.toUpperCase() !== protoVal) return false;
    }

    if (srcVal && !pkt.src_ip.toLowerCase().includes(srcVal)) return false;
    if (dstVal && !pkt.dst_ip.toLowerCase().includes(dstVal)) return false;

    return true;
  }

  // Render Table based on active filters
  function renderFilteredTable() {
    packetTableBody.innerHTML = "";
    const matching = allPackets.filter(packetMatchesFilter);

    if (matching.length === 0) {
      if (emptyStateRow) {
        emptyStateRow.style.display = "";
        packetTableBody.appendChild(emptyStateRow);
      }
      updateVisibleCount(0);
      return;
    }

    if (emptyStateRow) {
      emptyStateRow.style.display = "none";
    }

    const frag = document.createDocumentFragment();
    matching.slice(-200).forEach((pkt) => {
      frag.appendChild(createPacketRow(pkt));
    });

    packetTableBody.appendChild(frag);
    updateVisibleCount(matching.length);

    if (chkAutoScroll.checked) {
      tableContainer.scrollTop = tableContainer.scrollHeight;
    }
  }

  // Create table row element
  function createPacketRow(pkt) {
    const tr = document.createElement("tr");
    tr.className = "packet-row";
    tr.dataset.id = pkt.id;

    const badgeClass = getBadgeClass(pkt.protocol);

    tr.innerHTML = `
      <td>${pkt.id}</td>
      <td>${pkt.timestamp}</td>
      <td>${pkt.src_ip}${pkt.src_port !== '-' ? ':' + pkt.src_port : ''}</td>
      <td>${pkt.dst_ip}${pkt.dst_port !== '-' ? ':' + pkt.dst_port : ''}</td>
      <td><span class="badge ${badgeClass}">${pkt.protocol}</span></td>
      <td>${pkt.length} B</td>
      <td title="${escapeHtml(pkt.info)}">${escapeHtml(pkt.info)}</td>
    `;

    tr.addEventListener("click", () => openModal(pkt));
    return tr;
  }

  // Protocol badge class helper
  function getBadgeClass(protocol) {
    const p = (protocol || "").toLowerCase();
    if (p.includes("tcp")) return "badge-tcp";
    if (p.includes("udp")) return "badge-udp";
    if (p.includes("dns")) return "badge-dns";
    if (p.includes("icmp")) return "badge-icmp";
    if (p.includes("http")) return "badge-http";
    if (p.includes("arp")) return "badge-arp";
    return "badge-other";
  }

  // Refresh statistics counters and distribution bar
  async function refreshStats() {
    try {
      const res = await fetch("/api/stats");
      const stats = await res.json();

      statTotal.textContent = stats.total.toLocaleString();
      statTcp.textContent = (stats.tcp || 0).toLocaleString();
      statUdp.textContent = (stats.udp || 0).toLocaleString();
      statDns.textContent = (stats.dns || 0).toLocaleString();
      statIcmp.textContent = (stats.icmp || 0).toLocaleString();
      statBytes.textContent = formatBytes(stats.total_bytes || 0);

      // Calculate percentages for distribution bar
      const total = stats.total || 1;
      const pTcp = ((stats.tcp || 0) / total) * 100;
      const pUdp = ((stats.udp || 0) / total) * 100;
      const pDns = ((stats.dns || 0) / total) * 100;
      const pIcmp = ((stats.icmp || 0) / total) * 100;
      const pOther = Math.max(0, 100 - (pTcp + pUdp + pDns + pIcmp));

      barTcp.style.width = `${pTcp}%`;
      barUdp.style.width = `${pUdp}%`;
      barDns.style.width = `${pDns}%`;
      barIcmp.style.width = `${pIcmp}%`;
      barOther.style.width = `${pOther}%`;
    } catch (err) {
      console.error("Stats refresh error:", err);
    }
  }

  // Open Detailed Modal
  function openModal(pkt) {
    modalTitle.textContent = `Packet #${pkt.id} Breakdown`;
    modalProtocolBadge.textContent = pkt.protocol;
    modalProtocolBadge.className = `badge ${getBadgeClass(pkt.protocol)}`;

    modalLayers.textContent = pkt.layers || "Raw Packet";
    modalTime.textContent = pkt.timestamp;
    modalLength.textContent = `${pkt.length} Bytes`;
    modalSrc.textContent = pkt.src_ip;
    modalDst.textContent = pkt.dst_ip;
    modalSrcPort.textContent = pkt.src_port;
    modalDstPort.textContent = pkt.dst_port;
    modalInfo.textContent = pkt.info;
    modalPayload.textContent = pkt.payload || "No Payload";

    packetModal.classList.remove("hidden");
  }

  function closeModal() {
    packetModal.classList.add("hidden");
  }

  // UI state toggles
  function setCaptureActive(active, mode = "demo") {
    isCapturing = active;
    btnStart.disabled = active;
    btnStop.disabled = !active;
    captureModeSelect.disabled = active;
    interfaceSelect.disabled = active;

    if (active) {
      liveStatusBadge.className = "status-badge running";
      statusText.textContent = mode === "demo" ? "DEMO ACTIVE" : "LIVE CAPTURING";
    } else {
      liveStatusBadge.className = "status-badge stopped";
      statusText.textContent = "STOPPED";
    }
  }

  function updateVisibleCount(count) {
    visibleCountBadge.textContent = `Showing ${count} packet${count === 1 ? '' : 's'}`;
  }

  function showAlert(msg) {
    alertBanner.textContent = msg;
    alertBanner.classList.remove("hidden");
  }

  function hideAlert() {
    alertBanner.textContent = "";
    alertBanner.classList.add("hidden");
  }

  function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function debounce(fn, delay) {
    let timer = null;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), delay);
    };
  }
});
