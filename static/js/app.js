const API = "http://localhost:5000/api";

let me = null;
let myPass = null;
let activePeer = null;
let sessionMessages = []; // this session's message history — sessionStorage-backed

// ===== Notification System =====
let knownMessages = new Set();
let unreadCounts = {};
let pollingStarted = false;

// ===============================

const colors = [
  "#3b82f6",
  "#22c55e",
  "#a78bfa",
  "#f59e0b",
  "#ef4444",
  "#06b6d4",
  "#f97316",
];
function avatarColor(name) {
  let h = 0;
  for (let c of name) h = (h * 31 + c.charCodeAt(0)) % colors.length;
  return colors[h];
}

function initials(name) {
  return name.slice(0, 2).toUpperCase();
}

function timeStr() {
  return new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ===============================
// sessionMessages persistence helpers
// ===============================

function loadSessionMessages() {
  try {
    const raw = sessionStorage.getItem("cm_messages");
    sessionMessages = raw ? JSON.parse(raw) : [];
  } catch (e) {
    sessionMessages = [];
  }
}

function saveSessionMessages() {
  sessionStorage.setItem("cm_messages", JSON.stringify(sessionMessages));
}

// ===============================
// Session Check
// ===============================

(function () {
  const u = sessionStorage.getItem("cm_user");
  const p = sessionStorage.getItem("cm_pass");

  if (!u || !p) {
    window.location.href = "/login";
    return;
  }

  me = u;
  myPass = p;

  loadSessionMessages(); // restore history from this browser session (survives refresh)

  document.getElementById("user-badge").textContent = "● " + me;

  loadContacts();
  fetchMessages();

  if (!pollingStarted) {
    pollingStarted = true;
    setInterval(pollMessages, 2000);
  }
})();

// ===============================
// Logout
// ===============================

function doLogout() {
  sessionStorage.removeItem("cm_user");
  sessionStorage.removeItem("cm_pass");
  sessionStorage.removeItem("cm_messages"); // wipe history — this is the "forget everything" point

  sessionMessages = [];
  knownMessages.clear();
  unreadCounts = {};

  window.location.href = "/login";
}

// ===============================
// Register
// ===============================

function openRegModal() {
  window.location.href = "/register";
}

function closeRegModal() {}

// ===============================
// Contacts
// ===============================

async function loadContacts() {
  try {
    const r = await fetch(`${API}/users`);
    const d = await r.json();

    const list = document.getElementById("user-list");
    list.innerHTML = "";

    d.users
      .filter((u) => u !== me)
      .forEach((u) => {
        const unread = unreadCounts[u] || 0;
        const item = document.createElement("div");
        item.className = "user-item" + (u === activePeer ? " active" : "");
        item.innerHTML = `
          <div class="avatar"
          style="background:${avatarColor(u)}22;color:${avatarColor(u)}">
            ${initials(u)}
          </div>
          <div style="flex:1">
            <div class="uname">${u}</div>
            <div class="ustatus">
              🔒 end-to-end encrypted
            </div>
          </div>
          ${unread > 0 ? `<div class="unread-badge">${unread}</div>` : ""}
        `;
        item.onclick = () => openChat(u);
        list.appendChild(item);
      });
  } catch (e) {
    console.log(e);
  }
}

// ===============================
// Open Chat
// ===============================

async function openChat(peer) {
  activePeer = peer;
  unreadCounts[peer] = 0;

  document.getElementById("chat-title").textContent = peer;
  document.getElementById("compose-input").disabled = false;
  document.getElementById("btn-send").disabled = false;
  document.getElementById("compose-input").focus();

  loadContacts();
  renderMessages();
  await fetchMessages();
}

// ===============================
// Fetch Messages (server DELETES each file as it delivers it)
// ===============================

async function fetchMessages() {
  if (!me || !myPass) return;

  try {
    const r = await fetch(`${API}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: me, password: myPass }),
    });

    const d = await r.json();
    if (!r.ok) return;

    let changed = false;

    (d.messages || []).forEach((msg) => {
      if (!knownMessages.has(msg.filename)) {
        knownMessages.add(msg.filename);
        sessionMessages.push(msg);
        changed = true;
      }
    });

    if (changed) {
      saveSessionMessages();
      renderMessages();
    }
  } catch (e) {
    console.log(e);
  }
}

// ===============================
// Render Messages
// ===============================

function renderMessages() {
  const box = document.getElementById("messages");

  const convo = sessionMessages.filter(
    (m) => m.sender === activePeer || m.recipient === activePeer,
  );

  const all = [...convo].sort(
    (a, b) => (a.timestamp || 0) - (b.timestamp || 0),
  );

  if (all.length === 0) {
    box.innerHTML = `
      <div class="empty-chat">
        <div class="icon">💬</div>
        <p>No messages yet — say something!</p>
      </div>
    `;
    return;
  }

  box.innerHTML = "";

  all.forEach((msg, i) => {
    const sent = msg.sender === me;
    const row = document.createElement("div");
    row.className = "msg-row " + (sent ? "sent" : "received");
    const color = avatarColor(msg.sender);

    row.innerHTML = `
      <div class="bubble-avatar"
      style="background:${color}22;color:${color}">
        ${initials(msg.sender)}
      </div>
      <div class="bubble-wrap">
        <div class="bubble">
          ${msg.plaintext || "<em style='color:var(--text3)'>encrypted</em>"}
        </div>
        <div class="bubble-meta">
        <span class="bubble-time">
          ${
            msg.timestamp
              ? new Date(msg.timestamp).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                })
              : "--:--"
          }
        </span>
        </div>
      </div>
    `;

    row.dataset.idx = i;
    box.appendChild(row);
  });

  box.scrollTop = box.scrollHeight;
  window._allRendered = all;
}

// ===============================
// Send Message
// ===============================

async function doSend() {
  if (!me || !activePeer) return;

  const ta = document.getElementById("compose-input");
  const msg = ta.value.trim();
  if (!msg) return;

  ta.value = "";
  ta.style.height = "auto";

  try {
    const r = await fetch(`${API}/send`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sender: me,
        password: myPass,
        recipient: activePeer,
        message: msg,
      }),
    });

    const d = await r.json();
    if (!r.ok) return alert(d.error || "Send failed");

    // The server never stores or returns our own plaintext (forward
    // secrecy) — so we record what we sent directly into session history.
    sessionMessages.push({
      filename: `local_${Date.now()}`,
      sender: me,
      recipient: activePeer,
      timestamp: Date.now(),
      plaintext: msg,
      sig_valid: true,
      steps: d.steps,
    });
    saveSessionMessages();

    renderMessages();
    console.log("📤 Outgoing message:", msg);
    console.log("🔐 Encryption steps:", d.steps);
  } catch (e) {
    alert("Backend unreachable");
  }
}

// ===============================
// Poll Server Every 2 Seconds
// ===============================

async function pollMessages() {
  if (!me || !myPass) return;

  try {
    const r = await fetch(`${API}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: me, password: myPass }),
    });

    const d = await r.json();
    if (!r.ok) return;

    let changed = false;

    (d.messages || []).forEach((msg) => {
      if (!knownMessages.has(msg.filename)) {
        knownMessages.add(msg.filename);
        sessionMessages.push(msg);
        changed = true;

        if (msg.sender !== me && msg.sender !== activePeer) {
          unreadCounts[msg.sender] = (unreadCounts[msg.sender] || 0) + 1;
          showBrowserNotification(msg.sender);
        }
      }
    });

    if (changed) {
      saveSessionMessages();
      renderMessages();
      loadContacts();
      (d.messages || []).forEach((msg) => {
        if (msg.steps && msg.plaintext !== undefined) {
          console.log(`📨 Received message from ${msg.sender}:`, msg.plaintext);
          console.log("🔐 Decryption steps:", msg.steps);
          if (msg.sig_valid !== undefined) {
            console.log(
              "✓ Signature verification:",
              msg.sig_valid ? "VALID" : "INVALID",
            );
          }
        }
      });
    }
  } catch (e) {
    console.log(e);
  }
}

// ===============================
// Browser Notifications
// ===============================

if ("Notification" in window) {
  Notification.requestPermission();
}

function showBrowserNotification(sender) {
  if (Notification.permission === "granted") {
    new Notification("CryptoMesh", {
      body: `New encrypted message from ${sender}`,
      icon: "/static/icon.png",
    });
  }
}
