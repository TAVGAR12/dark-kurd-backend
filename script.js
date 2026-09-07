const output = document.getElementById("terminalOutput");
const runBtn = document.getElementById("runBtn");

const lines = [
  "[+] Checking server status...",
  "[+] Checking request logger...",
  "[+] Checking error monitor...",
  "[+] Checking rate monitor...",
  "[OK] Security monitoring online."
];

runBtn.addEventListener("click", () => {
  output.innerHTML = "";
  let i = 0;
  const timer = setInterval(() => {
    const p = document.createElement("div");
    p.textContent = lines[i++];
    output.appendChild(p);
    if (i >= lines.length) clearInterval(timer);
  }, 500);
});
