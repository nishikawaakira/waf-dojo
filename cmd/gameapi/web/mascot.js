"use strict";

// 案内役のキャラクター「まもりん」(柴犬の道場生)。画面の右下で吹き出しを出して話す。
//   Mascot.say(text, mood)  mood: "normal" | "happy" | "worried" | "surprised"
//   Mascot.celebrate()      紙吹雪を降らせて喜ぶ

const Mascot = (() => {
  const eyes = {
    normal: `<circle cx="45" cy="62" r="4.2" fill="#2b2d42"/><circle cx="75" cy="62" r="4.2" fill="#2b2d42"/>
             <circle cx="46.4" cy="60.6" r="1.4" fill="#fff"/><circle cx="76.4" cy="60.6" r="1.4" fill="#fff"/>`,
    happy: `<path d="M39 63 q6 -7 12 0" stroke="#2b2d42" stroke-width="3" fill="none" stroke-linecap="round"/>
            <path d="M69 63 q6 -7 12 0" stroke="#2b2d42" stroke-width="3" fill="none" stroke-linecap="round"/>`,
    worried: `<circle cx="45" cy="63" r="3.6" fill="#2b2d42"/><circle cx="75" cy="63" r="3.6" fill="#2b2d42"/>
              <path d="M38 54 l12 3" stroke="#7a4a1d" stroke-width="2.5" stroke-linecap="round"/>
              <path d="M82 54 l-12 3" stroke="#7a4a1d" stroke-width="2.5" stroke-linecap="round"/>`,
    surprised: `<circle cx="45" cy="62" r="5.5" fill="#2b2d42"/><circle cx="75" cy="62" r="5.5" fill="#2b2d42"/>
                <circle cx="47" cy="60" r="1.8" fill="#fff"/><circle cx="77" cy="60" r="1.8" fill="#fff"/>`,
  };
  const mouths = {
    normal: `<path d="M54 77 q6 6 12 0" stroke="#2b2d42" stroke-width="2.5" fill="none" stroke-linecap="round"/>`,
    happy: `<path d="M52 76 q8 12 16 0 z" fill="#e5737f" stroke="#2b2d42" stroke-width="2" stroke-linejoin="round"/>`,
    worried: `<path d="M54 81 q6 -5 12 0" stroke="#2b2d42" stroke-width="2.5" fill="none" stroke-linecap="round"/>`,
    surprised: `<ellipse cx="60" cy="80" rx="4" ry="5" fill="#e5737f" stroke="#2b2d42" stroke-width="2"/>`,
  };

  function svg(mood = "normal") {
    return `<svg viewBox="0 0 120 120" width="96" height="96" role="img" aria-hidden="true">
      <path d="M22 44 L30 8 L52 30 Z" fill="#e8913a"/><path d="M28 38 L32 18 L45 31 Z" fill="#fbd3a5"/>
      <path d="M98 44 L90 8 L68 30 Z" fill="#e8913a"/><path d="M92 38 L88 18 L75 31 Z" fill="#fbd3a5"/>
      <ellipse cx="60" cy="64" rx="42" ry="37" fill="#f2a65a"/>
      <ellipse cx="60" cy="79" rx="29" ry="20" fill="#fff6ea"/>
      <rect x="18" y="38" width="84" height="9" rx="4" fill="#e63946"/>
      <path d="M100 41 l14 -6 l-3 10 z M100 44 l13 6 l-9 3 z" fill="#e63946"/>
      <text x="60" y="46" font-size="8" text-anchor="middle" fill="#fff" font-weight="700">守</text>
      ${eyes[mood] || eyes.normal}
      <ellipse cx="60" cy="72" rx="4.5" ry="3.2" fill="#2b2d42"/>
      ${mouths[mood] || mouths.normal}
      <ellipse cx="35" cy="74" rx="6" ry="3.6" fill="#ff8fa3" opacity=".55"/>
      <ellipse cx="85" cy="74" rx="6" ry="3.6" fill="#ff8fa3" opacity=".55"/>
      <path d="M84 92 h22 v9 q0 11 -11 15 q-11 -4 -11 -15 z" fill="#4fb3ff" stroke="#1b6fa8" stroke-width="2"/>
      <path d="M89 102 l4 4 l8 -8" stroke="#fff" stroke-width="2.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
  }

  let root, bubble, face, hidden = false, tipIndex = 0, tips = () => [];

  function mount({ name, toggleLabel, tipTexts }) {
    tips = tipTexts;
    root = document.createElement("div");
    root.className = "mascot";
    root.innerHTML = `
      <div class="mascot-bubble" role="status" aria-live="polite"><strong class="mascot-name"></strong><span class="mascot-text"></span></div>
      <button class="mascot-face" type="button"></button>
      <button class="mascot-hide" type="button">×</button>`;
    document.body.appendChild(root);
    bubble = root.querySelector(".mascot-text");
    face = root.querySelector(".mascot-face");
    root.querySelector(".mascot-name").textContent = name;
    face.innerHTML = svg();
    face.setAttribute("aria-label", name);
    face.addEventListener("click", () => {
      if (hidden) return toggle();
      const list = tips();
      say(list[tipIndex++ % list.length], "happy");
    });
    root.querySelector(".mascot-hide").setAttribute("aria-label", toggleLabel);
    root.querySelector(".mascot-hide").addEventListener("click", toggle);
  }

  function rename(name, toggleLabel) {
    if (!root) return;
    root.querySelector(".mascot-name").textContent = name;
    face.setAttribute("aria-label", name);
    root.querySelector(".mascot-hide").setAttribute("aria-label", toggleLabel);
  }

  function toggle() {
    hidden = !hidden;
    root.classList.toggle("hidden", hidden);
  }

  function say(text, mood = "normal") {
    if (!root || !text) return;
    bubble.textContent = text;
    face.innerHTML = svg(mood);
    root.classList.remove("pop");
    void root.offsetWidth; // アニメーションをやり直す
    root.classList.add("pop");
  }

  function celebrate() {
    const colors = ["#4fb3ff", "#4cd2a0", "#ffc857", "#ff6b6b", "#c792ea", "#ff8fa3"];
    const layer = document.createElement("div");
    layer.className = "confetti";
    for (let i = 0; i < 90; i++) {
      const p = document.createElement("span");
      p.style.left = `${Math.random() * 100}%`;
      p.style.background = colors[i % colors.length];
      p.style.animationDelay = `${Math.random() * 0.6}s`;
      p.style.animationDuration = `${2 + Math.random() * 1.5}s`;
      p.style.transform = `rotate(${Math.random() * 360}deg)`;
      layer.appendChild(p);
    }
    document.body.appendChild(layer);
    setTimeout(() => layer.remove(), 4000);
    root?.classList.add("jump");
    setTimeout(() => root?.classList.remove("jump"), 1600);
  }

  return { mount, rename, say, celebrate, svg };
})();
